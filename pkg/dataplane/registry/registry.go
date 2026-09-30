// Package registry owns parser versions and the sole active-version pointer.
package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/sluice/pkg/dataplane/parsers"
)

var (
	ErrNotFound = errors.New("registry: parser not found")
	ErrConflict = errors.New("registry: active version changed")
)

type Info struct {
	ID            string   `json:"id"`
	Vendor        string   `json:"vendor"`
	Product       string   `json:"product"`
	Signature     string   `json:"signature"`
	ActiveVersion string   `json:"active_version"`
	Versions      []string `json:"versions"`
}

type entry struct {
	active   string
	versions map[string]*parsers.Parser
	yaml     map[string][]byte
}
type Registry struct {
	mu      sync.RWMutex
	engine  *parsers.Engine
	dir     string
	entries map[string]*entry
}

func New(engine *parsers.Engine, dir string) *Registry {
	if engine == nil {
		engine = parsers.New()
	}
	return &Registry{engine: engine, dir: dir, entries: map[string]*entry{}}
}

func (r *Registry) LoadDir() error {
	if r.dir == "" {
		return nil
	}
	if err := os.MkdirAll(r.dir, 0o750); err != nil {
		return err
	}
	if err := filepath.WalkDir(r.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		p, err := r.engine.Load(src)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		r.add(p, src, false)
		return nil
	}); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.entries {
		b, err := os.ReadFile(filepath.Join(r.dir, id, "active"))
		if err == nil {
			version := strings.TrimSpace(string(b))
			if e.versions[version] != nil {
				e.active = version
			}
		}
	}
	return nil
}

func (r *Registry) Add(src []byte, activate bool) (*parsers.Parser, error) {
	p, err := r.engine.Load(src)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addLocked(p, src, activate)
	if activate {
		return p, r.persistLocked(p.ID(), p.Version(), src)
	}
	return p, nil
}
func (r *Registry) add(p *parsers.Parser, src []byte, activate bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addLocked(p, src, activate)
}
func (r *Registry) addLocked(p *parsers.Parser, src []byte, activate bool) {
	e := r.entries[p.ID()]
	if e == nil {
		e = &entry{versions: map[string]*parsers.Parser{}, yaml: map[string][]byte{}}
		r.entries[p.ID()] = e
	}
	e.versions[p.Version()] = p
	e.yaml[p.Version()] = append([]byte(nil), src...)
	if activate || e.active == "" {
		e.active = p.Version()
	}
}

func (r *Registry) Active() []*parsers.Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*parsers.Parser, 0, len(ids))
	for _, id := range ids {
		e := r.entries[id]
		out = append(out, e.versions[e.active])
	}
	return out
}
func (r *Registry) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[id] != nil
}
func (r *Registry) Get(id, version string) (*parsers.Parser, []byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e := r.entries[id]
	if e == nil {
		return nil, nil, ErrNotFound
	}
	if version == "" {
		version = e.active
	}
	p := e.versions[version]
	if p == nil {
		return nil, nil, ErrNotFound
	}
	return p, append([]byte(nil), e.yaml[version]...), nil
}

func (r *Registry) Approve(src []byte) (*parsers.Parser, error) {
	var doc parsers.Document
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.entries[doc.ID]; e != nil {
		if doc.BaseVersion != e.active {
			return nil, ErrConflict
		}
		doc.Version = bumpPatch(e.active)
	}
	next, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	p, err := r.engine.Load(next)
	if err != nil {
		return nil, err
	}
	r.addLocked(p, next, true)
	if err := r.persistLocked(p.ID(), p.Version(), next); err != nil {
		return nil, err
	}
	return p, nil
}

func (r *Registry) Rollback(id, version string) (*parsers.Parser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[id]
	if e == nil || e.versions[version] == nil {
		return nil, ErrNotFound
	}
	e.active = version
	if r.dir != "" {
		return e.versions[version], os.WriteFile(filepath.Join(r.dir, id, "active"), []byte(version+"\n"), 0o640)
	}
	return e.versions[version], nil
}
func (r *Registry) List() []Info {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Info, 0, len(ids))
	for _, id := range ids {
		e := r.entries[id]
		p := e.versions[e.active]
		d := p.Document()
		versions := make([]string, 0, len(e.versions))
		for v := range e.versions {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		out = append(out, Info{ID: id, Vendor: p.Vendor(), Product: p.Product(), Signature: d.Match.Signature, ActiveVersion: e.active, Versions: versions})
	}
	return out
}
func (r *Registry) persistLocked(id, version string, src []byte) error {
	if r.dir == "" {
		return nil
	}
	dir := filepath.Join(r.dir, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, version+".yaml"), src, 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "active"), []byte(version+"\n"), 0o640)
}
func bumpPatch(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return version
	}
	n, _ := strconv.Atoi(parts[2])
	return parts[0] + "." + parts[1] + "." + strconv.Itoa(n+1)
}
