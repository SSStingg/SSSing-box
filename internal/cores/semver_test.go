package cores

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.0.2", "v1.0.1", 1},
		{"v1.0.1", "v1.0.2", -1},
		{"v1.0.2", "v1.0.2", 0},
		{"1.0.2", "v1.0.2", 0},              // v 前缀可有可无
		{"v2.0.0", "v1.0.2", 1},             // 大版本优先
		{"v1.1.1", "v1.0.9", 1},             // 数字段按数值比，不是字典序
		{"v1.10.0", "v1.9.9", 1},            // 10 > 9
		{"v1.2", "v1.2.0", 0},               // 缺失段按 0
		{"v1.15.0-alpha.13", "v1.15.0", -1}, // 预发布小于正式版
		{"v1.15.0-alpha.12", "v1.15.0-alpha.13", -1},
		{"v1.14.4", "v1.15.0-alpha.13", -1},
		{"v1.0.2", "v1.0.10", -1},
	}
	for _, c := range cases {
		if got := CompareSemver(c.a, c.b); got != c.want {
			t.Errorf("CompareSemver(%q, %q) = %d，想要 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestListReleasesFreshFiltersDraftAndPrerelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := []ghRelease{
			{TagName: "v1.0.3", Draft: true},
			{TagName: "v1.0.2", Pre: true},
			{TagName: "v1.0.1"},
			{TagName: "v1.0.0"},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	old := forgejoAPIBase
	forgejoAPIBase = srv.URL
	defer func() { forgejoAPIBase = old }()

	rels, err := ListReleasesFresh(PanelRepo)
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(rels) != 2 || rels[0].Tag != "v1.0.1" || rels[1].Tag != "v1.0.0" {
		t.Fatalf("草稿与预发布版应被过滤，得到 %v", rels)
	}
}

func TestListReleasesFreshAllKeepsPrerelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := []ghRelease{
			{TagName: "v1.15.0-alpha.13", Pre: true},
			{TagName: "v1.14.4"},
			{TagName: "v1.14.3", Draft: true},
			{TagName: "v1.14.2"},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	old := forgejoAPIBase
	forgejoAPIBase = srv.URL
	defer func() { forgejoAPIBase = old }()

	// 含测试版的列表：草稿过滤，预发布保留，按 semver 排。
	rels, err := ListReleasesFreshAll(PanelRepo)
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(rels) != 3 || rels[0].Tag != "v1.15.0-alpha.13" || rels[1].Tag != "v1.14.4" || rels[2].Tag != "v1.14.2" {
		t.Fatalf("预发布版应保留、草稿应过滤，得到 %v", rels)
	}
	// 正式版列表：预发布仍过滤。
	rels, err = ListReleasesFresh(PanelRepo)
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(rels) != 2 || rels[0].Tag != "v1.14.4" || rels[1].Tag != "v1.14.2" {
		t.Fatalf("正式版列表不应含预发布版，得到 %v", rels)
	}
	// releasesForVersion：不指定版本只取正式版；指定测试版时取全部列表。
	rels, err = releasesForVersion(PanelRepo, "")
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(rels) != 2 || rels[0].Tag != "v1.14.4" {
		t.Fatalf("空版本应只取正式版，得到 %v", rels)
	}
	rels, err = releasesForVersion(PanelRepo, "v1.15.0-alpha.13")
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(rels) != 3 || rels[0].Tag != "v1.15.0-alpha.13" {
		t.Fatalf("指定测试版时应取全部列表，得到 %v", rels)
	}
}

func TestListReleasesFreshSortsBySemver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API 返回顺序故意打乱，调用方必须自己按 semver 排。
		out := []ghRelease{{TagName: "v1.0.1"}, {TagName: "v1.0.10"}, {TagName: "v1.0.2"}}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	old := forgejoAPIBase
	forgejoAPIBase = srv.URL
	defer func() { forgejoAPIBase = old }()

	rels, err := ListReleasesFresh(PanelRepo)
	if err != nil {
		t.Fatalf("拉取失败：%v", err)
	}
	if len(rels) != 3 || rels[0].Tag != "v1.0.10" || rels[1].Tag != "v1.0.2" || rels[2].Tag != "v1.0.1" {
		t.Fatalf("应按 semver 从大到小排，得到 %v", rels)
	}
}

func TestApiBaseForUnknownRepo(t *testing.T) {
	if _, err := apiBaseFor("someone/else"); err == nil {
		t.Fatal("未知仓库应报错，不许默认走某一方")
	}
	if _, err := apiBaseFor(""); err == nil {
		t.Fatal("空仓库名应报错")
	}
	if base, err := apiBaseFor("sagernet/sing-box"); err != nil || base != upstreamAPIBase {
		t.Fatalf("内核仓库（大小写不敏感）应走 GitHub，得到 %q 错误 %v", base, err)
	}
}
