package stats

import "testing"

func TestParseNftRulesLoExclusion(t *testing.T) {
	out := []byte(`{"nftables": [
		{"rule": {"chain": "in", "handle": 10, "comment": "sssingbox-stats", "expr": [
			{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
			{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8443}},
			{"counter": {"bytes": 123}}
		]}},
		{"rule": {"chain": "in", "handle": 11, "comment": "sssingbox-stats", "expr": [
			{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8443}},
			{"counter": {"bytes": 456}}
		]}}
	]}`)
	rules, err := parseNftRules(out)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("想要 2 条规则，得到 %d", len(rules))
	}
	if !rules[0].NoLo {
		t.Errorf("带 iifname != lo 的规则应标记 NoLo")
	}
	if rules[1].NoLo {
		t.Errorf("不带回环排除的规则不应标记 NoLo")
	}
	if rules[0].Port != 8443 || rules[1].Port != 8443 {
		t.Errorf("端口解析错误：%+v", rules)
	}
}
