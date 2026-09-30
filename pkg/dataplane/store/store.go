// Package store keeps normalized event versions and their current pointers.
//
// Events are derived data: the vault holds the truth and a replay can rebuild
// every row. They live in SQLite so memory stays flat as the vault grows; an
// in-memory map cost ~3 KiB per event (4.7 GiB resident at one million) and
// sorted every key on each list request. The store opens with
// synchronous=OFF: after a crash the worst case is a missing tail, which the
// startup replay refills.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

var ErrNotFound = errors.New("store: event not found")

// Bodies are OCSF JSON: highly repetitive, ~1.4 KiB raw and ~10x smaller compressed.
// EncodeAll and DecodeAll are safe for concurrent use.
var (
	enc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	dec, _ = zstd.NewReader(nil)
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
  event_id    TEXT PRIMARY KEY,
  record_id   INTEGER NOT NULL,
  source_id   TEXT NOT NULL,
  parser_id   TEXT NOT NULL,
  is_current  INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  event_time  INTEGER,
  src_ip      TEXT NOT NULL,
  dst_ip      TEXT NOT NULL,
  body        BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_record ON events(record_id, event_id);
CREATE INDEX IF NOT EXISTS events_src ON events(src_ip, event_time) WHERE is_current = 1;
CREATE INDEX IF NOT EXISTS events_dst ON events(dst_ip, event_time) WHERE is_current = 1;`

// commitEvery bounds how much derived data a crash can lose. Committing per
// event cost ~70us of write syscalls; one transaction shared by everything
// that arrives within the window is what makes the store keep up with ingest.
const (
	commitEvery = 200 * time.Millisecond
	commitAfter = 5000
)

type Store struct {
	mu      sync.Mutex // one connection, one open transaction: reads see uncommitted writes
	db      *sql.DB
	tx      *sql.Tx
	insert  *sql.Stmt
	demote  *sql.Stmt
	pending int
	timer   *time.Timer
	count   int
	failed  bool
}

// New is an in-memory store, for tests and short-lived tools.
func New() *Store {
	s, err := Open(":memory:")
	if err != nil {
		panic(err) // an in-memory SQLite failing to open is a build problem, not a runtime one
	}
	return s
}

// Open opens (creating if needed) the store at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(OFF)&_pragma=busy_timeout(5000)"
	if path == ":memory:" {
		dsn = "file::memory:"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: create schema: %w", err)
	}
	s := &Store{db: db}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&s.count); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close commits what is pending and closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.commitLocked()
	return errors.Join(err, s.db.Close())
}

// begin opens the shared transaction if there is none. The caller holds mu.
func (s *Store) begin() error {
	if s.tx != nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	ins, err := tx.Prepare(`INSERT OR IGNORE INTO events(event_id, record_id, source_id, parser_id, is_current, received_at, event_time, src_ip, dst_ip, body)
		VALUES(?,?,?,?,1,?,?,?,?,?)`)
	if err == nil {
		s.insert = ins
		s.demote, err = tx.Prepare(`UPDATE events SET is_current = 0 WHERE record_id = ? AND event_id != ? AND is_current = 1`)
	}
	if err != nil {
		tx.Rollback()
		return err
	}
	s.tx = tx
	s.timer = time.AfterFunc(commitEvery, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.commitLocked(); err != nil {
			s.fail(err)
		}
	})
	return nil
}

func (s *Store) commitLocked() error {
	if s.tx == nil {
		return nil
	}
	s.timer.Stop()
	_ = s.insert.Close()
	_ = s.demote.Close()
	err := s.tx.Commit()
	s.tx, s.pending = nil, 0
	return err
}

func (s *Store) fail(err error) {
	if !s.failed { // once: a full disk would otherwise log once per event
		s.failed = true
		slog.Error("event store write failed; events stay in the vault and a replay rebuilds them", "err", err)
	}
}

func endpointIP(ocsf map[string]any, key string) string {
	endpoint, _ := ocsf[key].(map[string]any)
	value, _ := endpoint["ip"].(string)
	return value
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixNano()
}

// Put stores a new event version and makes it the current one for its record.
// It reports false, changing nothing, if that exact version is already stored.
func (s *Store) Put(event types.NormalizedEvent) bool {
	event.Current = true
	body, err := json.Marshal(event)
	if err != nil {
		s.mu.Lock()
		s.fail(err)
		s.mu.Unlock()
		return false
	}
	body = enc.EncodeAll(body, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		s.fail(err)
		return false
	}
	res, err := s.tx.Stmt(s.insert).Exec(event.EventID, event.RecordID, event.SourceID, event.ParserID,
		event.ReceivedAt.UnixNano(), nullTime(event.EventTime), endpointIP(event.OCSF, "src_endpoint"), endpointIP(event.OCSF, "dst_endpoint"), body)
	if err != nil {
		s.fail(err)
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}
	if _, err := s.tx.Stmt(s.demote).Exec(event.RecordID, event.EventID); err != nil {
		s.fail(err)
	}
	s.count++
	if s.pending++; s.pending >= commitAfter {
		if err := s.commitLocked(); err != nil {
			s.fail(err)
		}
	}
	return true
}

func encodeBody(e types.NormalizedEvent) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return enc.EncodeAll(b, nil), nil
}

func decode(body []byte, current bool) (types.NormalizedEvent, error) {
	var e types.NormalizedEvent
	raw, err := dec.DecodeAll(body, nil)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, err
	}
	e.Current = current // the column is authoritative; the body was written when the version was current
	return e, nil
}

// queryRow and query run on the shared transaction, so they see writes not yet committed.
func (s *Store) queryRow(q string, args ...any) *sql.Row {
	if s.begin() != nil {
		return s.db.QueryRow(q, args...)
	}
	return s.tx.QueryRow(q, args...)
}

func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	return s.tx.Query(q, args...)
}

func (s *Store) Get(id string) (types.NormalizedEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body []byte
	var current bool
	err := s.queryRow(`SELECT body, is_current FROM events WHERE event_id = ?`, id).Scan(&body, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return types.NormalizedEvent{}, ErrNotFound
	}
	if err != nil {
		return types.NormalizedEvent{}, err
	}
	return decode(body, current)
}

// List returns events newest record first, then by event id descending. after
// is the last event_id of the previous page.
func (s *Store) List(source, parser string, currentOnly bool, from, to *time.Time, after string, limit int) ([]types.NormalizedEvent, *string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var where []string
	var args []any
	if after != "" {
		var rec uint64
		if s.queryRow(`SELECT record_id FROM events WHERE event_id = ?`, after).Scan(&rec) == nil {
			where = append(where, `(record_id < ? OR (record_id = ? AND event_id < ?))`)
			args = append(args, rec, rec, after)
		}
	}
	if source != "" {
		where, args = append(where, `source_id = ?`), append(args, source)
	}
	if parser != "" {
		where, args = append(where, `parser_id = ?`), append(args, parser)
	}
	if currentOnly {
		where = append(where, `is_current = 1`)
	}
	if from != nil {
		where, args = append(where, `received_at >= ?`), append(args, from.UnixNano())
	}
	if to != nil {
		where, args = append(where, `received_at <= ?`), append(args, to.UnixNano())
	}
	q := `SELECT body, is_current FROM events`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	rows, err := s.query(q+` ORDER BY record_id DESC, event_id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return []types.NormalizedEvent{}, nil
	}
	defer rows.Close()
	out := make([]types.NormalizedEvent, 0, limit)
	more := false
	for rows.Next() {
		if len(out) == limit {
			more = true
			break
		}
		var body []byte
		var current bool
		if rows.Scan(&body, &current) != nil {
			continue
		}
		if e, err := decode(body, current); err == nil {
			out = append(out, e)
		}
	}
	if more {
		cursor := out[len(out)-1].EventID
		return out, &cursor
	}
	return out, nil
}

func (s *Store) CurrentByRecord(id types.RecordID) (types.NormalizedEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body []byte
	if s.queryRow(`SELECT body FROM events WHERE record_id = ? AND is_current = 1`, id).Scan(&body) != nil {
		return types.NormalizedEvent{}, false
	}
	e, err := decode(body, true)
	return e, err == nil
}

func (s *Store) Count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.count }

func (s *Store) MaxRecordID() types.RecordID {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max sql.NullInt64
	_ = s.queryRow(`SELECT MAX(record_id) FROM events`).Scan(&max)
	return types.RecordID(max.Int64)
}

// Reenrich recomputes the entities of current events that involve ip inside
// [from, to), after the resolver's answer for that address changed.
func (s *Store) Reenrich(ip string, from, to time.Time, resolve func(string, time.Time) []types.Entity) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.query(`SELECT event_id, body FROM events WHERE is_current = 1 AND event_time >= ? AND event_time < ? AND (src_ip = ? OR dst_ip = ?)`,
		from.UnixNano(), to.UnixNano(), ip, ip)
	if err != nil {
		return 0
	}
	type change struct {
		id   string
		body []byte
	}
	var changes []change
	for rows.Next() {
		var id string
		var body []byte
		if rows.Scan(&id, &body) != nil {
			continue
		}
		e, err := decode(body, true)
		if err != nil || e.EventTime == nil {
			continue
		}
		e.Entities = enrichEntities(e, resolve)
		if nb, err := encodeBody(e); err == nil {
			changes = append(changes, change{id, nb})
		}
	}
	rows.Close()
	for _, c := range changes {
		_, _ = s.tx.Exec(`UPDATE events SET body = ? WHERE event_id = ?`, c.body, c.id)
	}
	return len(changes)
}

func enrichEntities(event types.NormalizedEvent, resolve func(string, time.Time) []types.Entity) []types.Entity {
	out := []types.Entity{} // the contract says array, never null
	for _, role := range []string{"src", "dst"} {
		ip := endpointIP(event.OCSF, role+"_endpoint")
		for _, entity := range resolve(ip, *event.EventTime) {
			entity.Role = role
			out = append(out, entity)
		}
	}
	return out
}
