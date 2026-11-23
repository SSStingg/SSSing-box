package server

import (
	"sssingbox/internal/store"
	"sync"
	"testing"
	"time"
)

// checkQuotaLocked：超限额的节点被停用（库里 Enabled=false）。
// quotaThreshold(1000) = 999，上下行合计 1100 已超。
func TestCheckQuotaLockedDisablesOverQuota(t *testing.T) {
	s, st := setupChainTestServer(t)
	if err := st.UpsertInbound(&store.Inbound{ID: "q1", Name: "Q-OVER", Protocol: "vless", Port: 18999, Enabled: true, Config: "{}", QuotaMode: "total", QuotaBytes: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTraffic("q1", 500, 600); err != nil {
		t.Fatal(err)
	}
	s.checkQuotaLocked("q1")
	in, err := st.GetInbound("q1")
	if err != nil {
		t.Fatal(err)
	}
	if in.Enabled {
		t.Fatal("over-quota inbound should be disabled by checkQuotaLocked")
	}
}

// checkQuota（后台入口）：未超限额时直接返回，不动节点。
func TestCheckQuotaBackgroundKeepsUnderQuota(t *testing.T) {
	s, st := setupChainTestServer(t)
	if err := st.UpsertInbound(&store.Inbound{ID: "q2", Name: "Q-UNDER", Protocol: "vless", Port: 18998, Enabled: true, Config: "{}", QuotaMode: "total", QuotaBytes: 100000}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTraffic("q2", 10, 10); err != nil {
		t.Fatal(err)
	}
	s.checkQuota("q2")
	in, err := st.GetInbound("q2")
	if err != nil {
		t.Fatal(err)
	}
	if !in.Enabled {
		t.Fatal("under-quota inbound must stay enabled")
	}
}

// checkQuota（后台入口）：超限额时加锁复核后停用。
func TestCheckQuotaBackgroundDisablesOverQuota(t *testing.T) {
	s, st := setupChainTestServer(t)
	if err := st.UpsertInbound(&store.Inbound{ID: "q3", Name: "Q-BG", Protocol: "vless", Port: 18997, Enabled: true, Config: "{}", QuotaMode: "down", QuotaBytes: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTraffic("q3", 0, 1000); err != nil {
		t.Fatal(err)
	}
	s.checkQuota("q3")
	in, err := st.GetInbound("q3")
	if err != nil {
		t.Fatal(err)
	}
	if in.Enabled {
		t.Fatal("over-quota inbound should be disabled by background checkQuota")
	}
}

// PUT 路径已持 writeMu 时调 checkQuotaLocked 不能自死锁，
// 且停用仍生效（ApplyAll 在测试环境会失败，但库里先落盘，不影响断言）。
func TestCheckQuotaLockedUnderWriteMu(t *testing.T) {
	s, st := setupChainTestServer(t)
	if err := st.UpsertInbound(&store.Inbound{ID: "q4", Name: "Q-PUT", Protocol: "vless", Port: 18996, Enabled: true, Config: "{}", QuotaMode: "total", QuotaBytes: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTraffic("q4", 2000, 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.writeMu.Lock()
		s.checkQuotaLocked("q4")
		s.writeMu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("checkQuotaLocked under writeMu deadlocked")
	}
	in, err := st.GetInbound("q4")
	if err != nil {
		t.Fatal(err)
	}
	if in.Enabled {
		t.Fatal("over-quota inbound should be disabled by checkQuotaLocked under writeMu")
	}
}

// PublicIP/PublicIPv6 并发读缓存：-race 下必须干净（修复前会报 Data Race）。
// 先把缓存预热好，避免测试里真的去外网探测 IP。
func TestPublicIPConcurrentRace(t *testing.T) {
	s, _ := setupChainTestServer(t)
	s.app.publicIPCache = "203.0.113.9"
	s.app.publicIPv6Cache = "2001:db8::1"
	s.app.publicIPv6Fetched = time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got := s.app.PublicIP(); got != "203.0.113.9" {
				t.Errorf("PublicIP() = %q", got)
			}
		}()
		go func() {
			defer wg.Done()
			if got := s.app.PublicIPv6(); got != "2001:db8::1" {
				t.Errorf("PublicIPv6() = %q", got)
			}
		}()
	}
	wg.Wait()
}
