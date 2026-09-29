package registry

import (
	"context"
	"path/filepath"
	"testing"
)

func TestBeginFinishList(t *testing.T) {
	ctx := context.Background()
	r, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	id, err := r.Begin(ctx, Row{ProposalID: "prop-01", ParserID: "fortinet", FromVersion: "1.0.0", Action: ActionApprove,
		YAMLSHA256: YAMLSHA256("id: fortinet"), ApprovedBy: "nisha", Comment: "drift fix"})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := r.List(ctx, "fortinet", 0)
	if len(rows) != 1 || rows[0].Result != ResultPending {
		t.Fatalf("before Finish the row must exist as pending, got %+v", rows)
	}
	if err := r.Finish(ctx, id, ResultOK, "1.0.1", "replay-01", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Begin(ctx, Row{ParserID: "cisco_asa", Action: ActionRollback, ApprovedBy: "nisha"}); err != nil {
		t.Fatal(err)
	}
	rows, _ = r.List(ctx, "fortinet", 0)
	if rows[0].Result != ResultOK || rows[0].ToVersion != "1.0.1" || rows[0].ReplayJobID != "replay-01" {
		t.Fatalf("after Finish: %+v", rows[0])
	}
	all, _ := r.List(ctx, "", 0)
	if len(all) != 2 || all[0].ParserID != "cisco_asa" {
		t.Fatalf("List should return every parser newest first, got %+v", all)
	}
}

func TestRejectsAnonymousRows(t *testing.T) {
	r, _ := Open(":memory:")
	defer r.Close()
	if _, err := r.Begin(context.Background(), Row{ParserID: "x", Action: ActionApprove}); err == nil {
		t.Fatal("a row without a recorded name was accepted")
	}
	if _, err := r.Begin(context.Background(), Row{ParserID: "x", Action: "delete", ApprovedBy: "a"}); err == nil {
		t.Fatal("an unknown action was accepted")
	}
}

// A crash between Begin and Finish leaves the attempt on disk.
func TestPendingRowSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Begin(context.Background(), Row{ParserID: "fortinet", Action: ActionApprove, ApprovedBy: "nisha"}); err != nil {
		t.Fatal(err)
	}
	r.Close() // no Finish: the process "died" during the admin call
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	rows, _ := r2.List(context.Background(), "", 0)
	if len(rows) != 1 || rows[0].Result != ResultPending {
		t.Fatalf("want one pending row after reopen, got %+v", rows)
	}
}
