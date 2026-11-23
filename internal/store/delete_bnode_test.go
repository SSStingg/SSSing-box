package store

import (
	"testing"

	_ "modernc.org/sqlite"
)

// 删 B 节点时分流链只剩最后一组、且有兜底 B：
// 链不能整条消失，也不能留成空分流（之前会整条删除）——
// 应退化成 direct 模式走兜底 B，继续生效。
func TestDeleteBNodeLastRouteWithFallbackBecomesDirect(t *testing.T) {
	s, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, b := range []BNode{
		{ID: "b1", Name: "B1", Protocol: "vless", Link: "vless://x@1.1.1.1:443", Config: "{}", CreatedAt: 1},
		{ID: "b3", Name: "B3", Protocol: "ss", Link: "ss://x@2.2.2.2:8388", Config: "{}", CreatedAt: 1},
	} {
		if err := s.UpsertBNode(&b); err != nil {
			t.Fatal(err)
		}
	}
	ch := &Chain{ID: "c1", Name: "chain", InboundID: "in1", Mode: "split", BNodeID: "b3",
		Routes: []ChainRoute{{BNodeID: "b1", List: "example.com"}}, Enabled: true, CreatedAt: 1}
	if err := s.UpsertChain(ch); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBNode("b1"); err != nil {
		t.Fatalf("delete b1: %v", err)
	}
	chains, err := s.ListChains()
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("chain should survive as direct, got %d chains", len(chains))
	}
	got := chains[0]
	if got.Mode != "direct" || got.BNodeID != "b3" || len(got.Routes) != 0 {
		t.Fatalf("want direct/b3/no-routes, got %+v", got)
	}
	// 无兜底时仍整条删除。
	ch2 := &Chain{ID: "c2", Name: "chain2", InboundID: "in2", Mode: "split", BNodeID: "",
		Routes: []ChainRoute{{BNodeID: "b3", List: "example.com"}}, Enabled: true, CreatedAt: 1}
	if err := s.UpsertChain(ch2); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBNode("b3"); err != nil {
		t.Fatalf("delete b3: %v", err)
	}
	chains, err = s.ListChains()
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Fatalf("chain without fallback should be deleted, got %+v", chains)
	}
}
