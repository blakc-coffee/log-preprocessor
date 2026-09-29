// Package registry is the control plane's approval history: who approved,
// rejected or rolled back which parser version, when, and what happened.
//
// It does not decide what the data plane runs (decision D10: the data plane
// owns the active parser set). It is the audit trail, and the control plane
// is the only caller of approve and rollback on the admin API.
//
// A row is written before the admin call and updated after it, so a crash in
// between leaves a "pending" row as evidence of the attempt.
package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

// Actions recorded in the registry.
const (
	ActionApprove  = "approve"
	ActionReject   = "reject"
	ActionRollback = "rollback"
)

// Results a row can end in. ResultPending means the admin call has not
// returned (or the process died before it did).
const (
	ResultPending = "pending"
	ResultOK      = "ok"
	ResultStale   = "stale"
	ResultError   = "error"
)

// Row is one audit entry.
type Row struct {
	ID          int64     `json:"id"`
	ProposalID  string    `json:"proposal_id"`
	ParserID    string    `json:"parser_id"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Action      string    `json:"action"`
	YAMLSHA256  string    `json:"yaml_sha256"`
	ApprovedBy  string    `json:"approved_by"` // a recorded name; there is no authentication in v1
	Comment     string    `json:"comment"`
	At          time.Time `json:"at"`
	ReplayJobID string    `json:"replay_job_id"`
	Result      string    `json:"result"`
	Error       string    `json:"error"`
}

// Registry is a SQLite-backed approval history. Safe for concurrent use.
type Registry struct {
	db  *sql.DB
	now func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS approvals(
  id INTEGER PRIMARY KEY,
  proposal_id TEXT NOT NULL DEFAULT '',
  parser_id TEXT NOT NULL,
  from_version TEXT NOT NULL DEFAULT '',
  to_version TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL CHECK (action IN ('approve','reject','rollback')),
  yaml_sha256 TEXT NOT NULL DEFAULT '',
  approved_by TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL,
  replay_job_id TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS approvals_parser ON approvals(parser_id, id);`

// Open opens (creating if needed) the registry at path. ":memory:" gives a
// private in-memory database, for tests and --mock runs without a path.
func Open(path string) (*Registry, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"
	if path == ":memory:" {
		dsn = "file::memory:"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite has one writer anyway, and an in-memory database
	// exists per connection.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("registry: create schema: %w", err)
	}
	return &Registry{db: db, now: time.Now}, nil
}

// Close closes the database.
func (r *Registry) Close() error { return r.db.Close() }

// YAMLSHA256 is the hash recorded for a parser document.
func YAMLSHA256(yaml string) string {
	s := sha256.Sum256([]byte(yaml))
	return hex.EncodeToString(s[:])
}

// Begin records an attempt before the admin call and returns its id. The row
// starts as ResultPending.
func (r *Registry) Begin(ctx context.Context, row Row) (int64, error) {
	if row.ParserID == "" || row.ApprovedBy == "" {
		return 0, errors.New("registry: parser_id and approved_by are required")
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO approvals
		(proposal_id, parser_id, from_version, to_version, action, yaml_sha256, approved_by, comment, at, result)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		row.ProposalID, row.ParserID, row.FromVersion, row.ToVersion, row.Action, row.YAMLSHA256, row.ApprovedBy, row.Comment,
		r.now().UTC().UnixMicro(), ResultPending)
	if err != nil {
		return 0, fmt.Errorf("registry: begin: %w", err)
	}
	return res.LastInsertId()
}

// Finish records how the admin call ended.
func (r *Registry) Finish(ctx context.Context, id int64, result, toVersion, replayJobID, errMsg string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE approvals SET result=?, to_version=CASE WHEN ?='' THEN to_version ELSE ? END,
		replay_job_id=?, error=? WHERE id=?`, result, toVersion, toVersion, replayJobID, errMsg, id)
	if err != nil {
		return fmt.Errorf("registry: finish: %w", err)
	}
	return nil
}

// List returns rows newest first, for one parser when parserID is set.
func (r *Registry) List(ctx context.Context, parserID string, limit int) ([]Row, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, proposal_id, parser_id, from_version, to_version, action, yaml_sha256, approved_by, comment, at,
		replay_job_id, result, error FROM approvals`
	args := []any{}
	if parserID != "" {
		q += ` WHERE parser_id = ?`
		args = append(args, parserID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("registry: list: %w", err)
	}
	defer rows.Close()
	out := []Row{}
	for rows.Next() {
		var x Row
		var at int64
		if err := rows.Scan(&x.ID, &x.ProposalID, &x.ParserID, &x.FromVersion, &x.ToVersion, &x.Action, &x.YAMLSHA256,
			&x.ApprovedBy, &x.Comment, &at, &x.ReplayJobID, &x.Result, &x.Error); err != nil {
			return nil, err
		}
		x.At = time.UnixMicro(at).UTC()
		out = append(out, x)
	}
	return out, rows.Err()
}
