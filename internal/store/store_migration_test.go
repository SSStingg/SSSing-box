package store

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// 老库升级：mode 列是后加的，没有它的旧 chains 表打开后必须自动补列，
// 老链式读出来 mode 为空 = 分流，行为和升级前一致。
func TestMigrateChainsModeColumn(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/old.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE chains(id TEXT PRIMARY KEY, name TEXT NOT NULL, inbound_id TEXT NOT NULL, list TEXT NOT NULL DEFAULT '', bnode_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO chains(id,name,inbound_id,list,bnode_id,enabled,created_at) VALUES('c1','old','in1','example.com','b1',1,123)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	defer s.Close()
	list, err := s.ListChains()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != "c1" || list[0].Mode != "" {
		t.Fatalf("old chain should read back with empty mode, got %+v", list)
	}
	// 补列后新链式能正常存 mode。
	if err := s.UpsertChain(&Chain{ID: "c2", Name: "d", InboundID: "in2", Mode: "direct", BNodeID: "b1", Enabled: true, CreatedAt: 124}); err != nil {
		t.Fatalf("upsert direct: %v", err)
	}
	list, _ = s.ListChains()
	for _, c := range list {
		if c.ID == "c2" && c.Mode != "direct" {
			t.Fatalf("direct chain should keep mode, got %+v", c)
		}
	}
}
