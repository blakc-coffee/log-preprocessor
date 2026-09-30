package main

// sluice tui: a full-screen terminal client for a RUNNING Sluice. It only talks to the control
// plane's HTTP API (and the HTTP ingest port to send files), so it works the same against the
// Docker deployment, a native `sluice all`, or a remote host.

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tuiClient struct {
	base, ingest, user, pass string
	http                     *http.Client
}

func (c *tuiClient) do(method, path string, body []byte, out any) error {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("401: sign-in required (use --user / --password)")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

type telemetry struct {
	EPS              float64 `json:"eps_1m"`
	EventsTotal      int     `json:"events_total"`
	QuarantineOpen   int     `json:"quarantine_open"`
	QuarantinedTotal int     `json:"quarantined_total"`
	Lossless         struct {
		OK bool   `json:"last_verify_ok"`
		At string `json:"last_verify_at"`
	} `json:"lossless"`
	Sources []struct {
		ID      string  `json:"id"`
		EPS     float64 `json:"eps"`
		Records int     `json:"records"`
	} `json:"sources"`
	Vault struct {
		Records   int    `json:"records"`
		Segments  int    `json:"segments"`
		Sealed    int    `json:"sealed_through"`
		ChainHead string `json:"chain_head"`
		Failed    bool   `json:"failed"`
	} `json:"vault"`
}

type event struct {
	EventID    string          `json:"event_id"`
	RecordID   int             `json:"record_id"`
	SourceID   string          `json:"source_id"`
	ParserID   string          `json:"parser_id"`
	EventTime  string          `json:"event_time"`
	Confidence float64         `json:"parse_confidence"`
	SHA        string          `json:"raw_sha256"`
	OCSF       json.RawMessage `json:"ocsf"`
}
type eventsResp struct {
	Events []event `json:"events"`
}
type quarantineResp struct {
	Records []struct {
		RecordID int    `json:"record_id"`
		SourceID string `json:"source_id"`
		Stage    string `json:"failure_stage"`
		Error    string `json:"error"`
		Status   string `json:"status"`
	} `json:"records"`
	Summary []struct {
		SourceID string `json:"source_id"`
		Open     int    `json:"open"`
		Resolved int    `json:"resolved"`
	} `json:"summary"`
}
type proposal struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	ParserID string `json:"parser_id"`
	SourceID string `json:"source_id"`
	Status   string `json:"status"`
	YAML     string `json:"yaml"`
}
type proposalsResp struct {
	Proposals []proposal `json:"proposals"`
}
type verifyRes struct {
	OK       bool   `json:"ok"`
	Deep     bool   `json:"deep"`
	Segments int    `json:"segments"`
	Records  int    `json:"records"`
	Head     string `json:"head"`
	Error    string `json:"error"`
}

type (
	tickMsg   time.Time
	errMsg    struct{ err error }
	noteMsg   string // a one-line result shown in the footer
	detailMsg string // text for the detail pane
)

func get[T any](c *tuiClient, path string) tea.Cmd {
	return func() tea.Msg {
		var v T
		if err := c.do("GET", path, nil, &v); err != nil {
			return errMsg{err}
		}
		return v
	}
}

var tabNames = []string{"Dashboard", "Events", "Quarantine", "Proposals", "Vault"}

const (
	tDash = iota
	tEvents
	tQuar
	tProps
	tVault
)

type model struct {
	c          *tuiClient
	tab        int
	w, h       int
	cursor     [5]int
	tele       telemetry
	events     []event
	quar       quarantineResp
	props      []proposal
	vfy        verifyRes
	detail     string
	dscroll    int
	note, warn string
	mode       string // "", "confirm", "path", "source"
	buf, path  string
}

func newModel(c *tuiClient) model { return model{c: c, w: 100, h: 30} }

func (m model) Init() tea.Cmd { return tea.Batch(m.refresh(), tick()) }

func tick() tea.Cmd { return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }

// refresh reloads telemetry and whatever the current tab shows.
func (m model) refresh() tea.Cmd {
	cmds := []tea.Cmd{get[telemetry](m.c, "/api/telemetry")}
	switch m.tab {
	case tEvents:
		cmds = append(cmds, get[eventsResp](m.c, "/api/events?limit=200"))
	case tQuar:
		cmds = append(cmds, get[quarantineResp](m.c, "/api/quarantine"))
	case tProps:
		cmds = append(cmds, get[proposalsResp](m.c, "/api/proposals"))
	case tVault:
		cmds = append(cmds, get[verifyRes](m.c, "/api/vault/verify"))
	}
	return tea.Batch(cmds...)
}

func (m model) rows() int {
	switch m.tab {
	case tEvents:
		return len(m.events)
	case tQuar:
		return len(m.quar.Records)
	case tProps:
		return len(m.props)
	}
	return 0
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if msg.Width > 0 && msg.Height > 0 { // some terminals report 0x0 at startup
			m.w, m.h = msg.Width, msg.Height
		}
	case tickMsg:
		return m, tea.Batch(m.refresh(), tick())
	case telemetry:
		m.tele, m.warn = msg, ""
	case eventsResp:
		m.events = msg.Events
	case quarantineResp:
		m.quar = msg
	case proposalsResp:
		m.props = msg.Proposals
	case verifyRes:
		// The periodic quick check must not replace a deep result for the same vault state.
		if !(m.vfy.Deep && !msg.Deep && msg.Head == m.vfy.Head && msg.Records == m.vfy.Records) {
			m.vfy = msg
		}
		if msg.Deep {
			m.note = ""
		}
	case errMsg:
		m.warn = msg.err.Error()
	case noteMsg:
		m.note = string(msg)
		return m, m.refresh()
	case detailMsg:
		m.detail, m.dscroll = string(msg), 0
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.mode { // modal input first
	case "confirm":
		m.mode = ""
		if s == "y" || s == "Y" {
			return m, m.approve()
		}
		m.note = "cancelled"
		return m, nil
	case "path", "source":
		return m.typing(k)
	}
	if m.detail != "" { // the detail pane scrolls; esc closes it
		switch s {
		case "esc", "q", "enter":
			m.detail = ""
		case "down", "j":
			m.dscroll++
		case "up", "k":
			if m.dscroll > 0 {
				m.dscroll--
			}
		}
		return m, nil
	}
	m.note = ""
	switch s {
	case "q":
		return m, tea.Quit
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % len(tabNames)
	case "shift+tab", "left", "h":
		m.tab = (m.tab + len(tabNames) - 1) % len(tabNames)
	case "1", "2", "3", "4", "5":
		m.tab = int(s[0] - '1')
	case "down", "j":
		if m.cursor[m.tab] < m.rows()-1 {
			m.cursor[m.tab]++
		}
	case "up", "k":
		if m.cursor[m.tab] > 0 {
			m.cursor[m.tab]--
		}
	case "r":
		m.note = "refreshed"
	case "i":
		m.mode, m.buf = "path", ""
		return m, nil
	case "enter":
		return m, m.open()
	case "a":
		if m.tab == tProps && len(m.props) > 0 {
			if p := m.props[m.cursor[tProps]]; p.Status == "pending" {
				m.mode = "confirm"
			} else {
				m.note = "only pending proposals can be approved"
			}
		}
		return m, nil
	case "v":
		if m.tab == tVault {
			m.note = "verifying every record (deep)…"
			return m, get[verifyRes](m.c, "/api/vault/verify?deep=true")
		}
	}
	return m, m.refresh()
}

func (m model) typing(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyEsc:
		m.mode, m.buf = "", ""
	case tea.KeyBackspace:
		if r := []rune(m.buf); len(r) > 0 {
			m.buf = string(r[:len(r)-1])
		}
	case tea.KeySpace:
		m.buf += " "
	case tea.KeyRunes:
		m.buf += string(k.Runes)
	case tea.KeyEnter:
		if m.mode == "path" {
			m.path, m.mode = expandHome(strings.TrimSpace(m.buf)), "source"
			m.buf = strings.TrimSuffix(filepath.Base(m.path), filepath.Ext(m.path))
			return m, nil
		}
		id, path := strings.TrimSpace(m.buf), m.path
		m.mode, m.buf = "", ""
		return m, m.send(path, id)
	}
	return m, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

// send POSTs a whole file to the HTTP ingest port. The last path segment is the source id.
func (m model) send(path, id string) tea.Cmd {
	c := m.c
	return func() tea.Msg {
		b, err := os.ReadFile(path)
		if err != nil {
			return errMsg{err}
		}
		req, _ := http.NewRequest("POST", c.ingest+"/ingest/"+url.PathEscape(id), bytes.NewReader(b))
		resp, err := c.http.Do(req)
		if err != nil {
			return errMsg{fmt.Errorf("ingest %s: %w", c.ingest, err)}
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			return errMsg{fmt.Errorf("ingest: %s", resp.Status)}
		}
		return noteMsg(fmt.Sprintf("sent %s (%d bytes) as source %q: %s", filepath.Base(path), len(b), id, resp.Status))
	}
}

func (m model) approve() tea.Cmd {
	c, p := m.c, m.props[m.cursor[tProps]]
	who := c.user
	if who == "" {
		who = os.Getenv("USER")
	}
	if who == "" {
		who = "tui"
	}
	return func() tea.Msg {
		body, _ := json.Marshal(map[string]string{"approved_by": who, "comment": "approved in sluice tui"})
		var res struct {
			Version string `json:"version"`
			Job     string `json:"replay_job_id"`
		}
		if err := c.do("POST", "/api/proposals/"+url.PathEscape(p.ID)+"/approve", body, &res); err != nil {
			return errMsg{err}
		}
		for i := 0; i < 20 && res.Job != ""; i++ { // the replay is quick; poll until it finishes
			var j struct {
				State     string `json:"state"`
				Processed int    `json:"processed"`
				Succeeded int    `json:"succeeded"`
			}
			time.Sleep(500 * time.Millisecond)
			if c.do("GET", "/api/replay/"+res.Job, nil, &j) == nil && j.State != "running" && j.State != "queued" {
				return noteMsg(fmt.Sprintf("approved %s v%s; replay %s: %d of %d re-parsed", p.ParserID, res.Version, j.State, j.Succeeded, j.Processed))
			}
		}
		return noteMsg(fmt.Sprintf("approved %s v%s (replay %s started)", p.ParserID, res.Version, res.Job))
	}
}

// open shows the selected row in the detail pane.
func (m model) open() tea.Cmd {
	c := m.c
	switch m.tab {
	case tEvents:
		if len(m.events) == 0 {
			return nil
		}
		e := m.events[m.cursor[tEvents]]
		return func() tea.Msg {
			var raw struct {
				B64 string `json:"raw_base64"`
			}
			if err := c.do("GET", "/api/events/"+url.PathEscape(e.EventID)+"/raw", nil, &raw); err != nil {
				return errMsg{err}
			}
			b, _ := base64.StdEncoding.DecodeString(raw.B64)
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, e.OCSF, "", "  ")
			return detailMsg(fmt.Sprintf("event    %s\nparser   %s   confidence %.2f\nsha256   %s   (of the raw bytes below)\n\nRAW\n%s\n\nOCSF\n%s",
				e.EventID, e.ParserID, e.Confidence, e.SHA, strconv.Quote(string(b)), pretty.String()))
		}
	case tProps:
		if len(m.props) == 0 {
			return nil
		}
		p := m.props[m.cursor[tProps]]
		return func() tea.Msg {
			return detailMsg(fmt.Sprintf("%s   %s   status %s\nsource %s\n\n%s", p.ID, p.Kind, p.Status, p.SourceID, p.YAML))
		}
	}
	return nil
}

var (
	accent = lipgloss.Color("#3fcb7f")
	dim    = lipgloss.Color("#7d8590")
	bad    = lipgloss.Color("#f85149")
	selSty = lipgloss.NewStyle().Foreground(lipgloss.Color("#050607")).Background(accent)
	dimSty = lipgloss.NewStyle().Foreground(dim)
	badSty = lipgloss.NewStyle().Foreground(bad).Bold(true)
	okSty  = lipgloss.NewStyle().Foreground(accent).Bold(true)
)

func (m model) fit(s string) string { return lipgloss.NewStyle().MaxWidth(m.w).Render(s) }

func (m model) View() string {
	var head []string
	for i, n := range tabNames {
		label := fmt.Sprintf(" %d %s ", i+1, n)
		if i == m.tab {
			label = selSty.Render(label)
		} else {
			label = dimSty.Render(label)
		}
		head = append(head, label)
	}
	body := m.body()
	if m.detail != "" {
		body = m.detailView()
	}
	foot := m.footer()
	pad := m.h - lipgloss.Height(body) - 4
	if pad < 0 {
		pad = 0
	}
	return m.fit(okSty.Render("sluice")+"  "+strings.Join(head, "")) + "\n\n" + body + strings.Repeat("\n", pad) + "\n\n" + foot
}

func (m model) footer() string {
	switch m.mode {
	case "confirm":
		p := m.props[m.cursor[tProps]]
		return badSty.Render(fmt.Sprintf("Approve %s for source %q and replay the quarantine? (y/n)", p.ParserID, p.SourceID))
	case "path":
		return "File to ingest: " + m.buf + "█   " + dimSty.Render("enter next · esc cancel")
	case "source":
		return "Source id for " + filepath.Base(m.path) + ": " + m.buf + "█   " + dimSty.Render("enter send · esc cancel")
	}
	switch {
	case m.warn != "":
		return m.fit(badSty.Render("! " + m.warn))
	case m.note != "":
		return m.fit(okSty.Render(m.note))
	}
	keys := "tab/1-5 switch · ↑↓ select · i ingest a file · r refresh · q quit"
	switch m.tab {
	case tEvents:
		keys = "enter open event · " + keys
	case tProps:
		keys = "enter view · a approve · " + keys
	case tVault:
		keys = "v deep verify · " + keys
	}
	return dimSty.Render(m.fit(keys))
}

func (m model) detailView() string {
	lines := strings.Split(m.detail, "\n")
	room := m.h - 6
	if room < 3 {
		room = 3
	}
	if m.dscroll > len(lines)-1 {
		m.dscroll = len(lines) - 1
	}
	end := m.dscroll + room
	if end > len(lines) {
		end = len(lines)
	}
	out := make([]string, 0, room+1)
	for _, l := range lines[m.dscroll:end] {
		out = append(out, m.fit(l))
	}
	return strings.Join(out, "\n") + "\n" + dimSty.Render("↑↓ scroll · esc close")
}

func (m model) body() string {
	switch m.tab {
	case tDash:
		return m.dashboard()
	case tEvents:
		return m.list("time                      source             parser              conf  event", 0, len(m.events), func(i int) string {
			e := m.events[i]
			return fmt.Sprintf("%-24s  %-18s %-19s %4.2f  %s", short(e.EventTime, 24), short(e.SourceID, 18), short(e.ParserID, 19), e.Confidence, e.EventID)
		})
	case tQuar:
		var sum []string
		for _, s := range m.quar.Summary {
			sum = append(sum, fmt.Sprintf("  %-22s open %-5d resolved %d", s.SourceID, s.Open, s.Resolved))
		}
		head := okSty.Render("Unparsed records, kept byte-exact in the vault") + "\n" + strings.Join(sum, "\n") + "\n\n"
		return head + m.list("record  source              stage    reason", len(m.quar.Summary)+3, len(m.quar.Records), func(i int) string {
			r := m.quar.Records[i]
			return fmt.Sprintf("%-7d %-19s %-8s %s [%s]", r.RecordID, short(r.SourceID, 19), r.Stage, r.Error, r.Status)
		})
	case tProps:
		return okSty.Render("Parser proposals from the intelligence sidecar. Nothing activates until you approve.") + "\n\n" +
			m.list("id                 kind  status     source                parser", 2, len(m.props), func(i int) string {
				p := m.props[i]
				return fmt.Sprintf("%-18s %-5s %-10s %-21s %s", p.ID, p.Kind, p.Status, short(p.SourceID, 21), p.ParserID)
			})
	default:
		return m.vault()
	}
}

func (m model) list(head string, extra, n int, row func(int) string) string {
	if n == 0 {
		return dimSty.Render("(nothing here yet)")
	}
	room := m.h - 10 - extra // header, footer, list head and counter take the rest
	if room < 3 {
		room = 3
	}
	cur := m.cursor[m.tab]
	if cur >= n {
		cur = n - 1
	}
	start := 0
	if cur >= room {
		start = cur - room + 1
	}
	end := start + room
	if end > n {
		end = n
	}
	out := []string{dimSty.Render(m.fit(head))}
	for i := start; i < end; i++ {
		l := m.fit(row(i))
		if i == cur {
			l = selSty.Render(l)
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n" + dimSty.Render(fmt.Sprintf("%d/%d", cur+1, n))
}

func (m model) dashboard() string {
	t := m.tele
	v := okSty.Render("intact")
	if !t.Lossless.OK {
		v = badSty.Render("NOT VERIFIED")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s   %d events parsed   %s   %d records in vault\n", okSty.Render(fmt.Sprintf("%.1f events/s", t.EPS)), t.EventsTotal, badSty.Render(fmt.Sprintf("%d quarantined", t.QuarantineOpen)), t.Vault.Records)
	fmt.Fprintf(&b, "vault %s   %d segment(s)   chain head %s\n\n", v, t.Vault.Segments, short(t.Vault.ChainHead, 24))
	b.WriteString(dimSty.Render("source                  records   events/s") + "\n")
	for _, s := range t.Sources {
		fmt.Fprintf(&b, "%-22s  %7d   %8.1f\n", short(s.ID, 22), s.Records, s.EPS)
	}
	if len(t.Sources) == 0 {
		b.WriteString(dimSty.Render("no data yet: press i and give a log file to ingest") + "\n")
	}
	return b.String()
}

func (m model) vault() string {
	v, t := m.vfy, m.tele
	state := okSty.Render("INTACT")
	if !v.OK {
		state = badSty.Render("PROBLEM " + v.Error)
	}
	kind := "quick check"
	if v.Deep {
		kind = "deep check: every record re-read and every segment root recomputed"
	}
	return fmt.Sprintf("Chain %s   (%s)\n\nsegments   %d\nrecords    %d\nchain head %s\n\nThe vault is the system of record: everything else can be rebuilt from it.\nPress v to re-read and re-hash every record.",
		state, kind, v.Segments, max(v.Records, t.Vault.Records), v.Head)
}

func short(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func runTUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	env := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	base := fs.String("url", env("SLUICE_URL", "http://127.0.0.1:8000"), "control plane URL")
	ingest := fs.String("ingest-url", env("SLUICE_INGEST_URL", "http://127.0.0.1:8080"), "HTTP ingest URL (used to send files)")
	user := fs.String("user", env("SLUICE_USER", ""), "sign-in name, if the control plane requires one")
	pass := fs.String("password", env("SLUICE_PASSWORD", ""), "sign-in password")
	insecure := fs.Bool("insecure", false, "accept a self-signed TLS certificate")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	lipgloss.SetHasDarkBackground(true) // skip the terminal background query: it can stall on terminals that never answer
	tr := &http.Transport{Proxy: nil}
	if *insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in flag
	}
	c := &tuiClient{base: strings.TrimRight(*base, "/"), ingest: strings.TrimRight(*ingest, "/"), user: *user, pass: *pass,
		http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
	if err := c.do("GET", "/api/telemetry", nil, nil); err != nil {
		fmt.Fprintf(stderr, "sluice tui: no Sluice is answering at %s (%v).\nStart one first, in another terminal:  sluice all   (or: docker compose up -d)\nThen run  sluice tui  again.\n", c.base, err)
		return exitFailure
	}
	if _, err := tea.NewProgram(newModel(c), tea.WithAltScreen(), tea.WithOutput(stdout)).Run(); err != nil {
		fmt.Fprintln(stderr, "sluice tui:", err)
		return exitFailure
	}
	return exitOK
}
