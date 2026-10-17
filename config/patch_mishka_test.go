//go:build mishka

package config

import (
	"reflect"
	"slices"
	"testing"
)

func TestMishkaVPNPatchDoesNotChangeRoot(t *testing.T) {
	for _, fd := range []int{0, 42} {
		cfg := DefaultRawConfig()
		cfg.DNS.Enable = true
		cfg.Interface = "wlan0"
		cfg.RoutingMark = 123
		cfg.ExternalControllerTLS = "127.0.0.1:9443"
		cfg.RedirPort = 7892
		cfg.TProxyPort = 7893
		cfg.Tun.FileDescriptor = fd
		cfg.Tun.CongestionController = "bbr"
		cfg.Tun.IncludePackage = []string{"example.include"}
		cfg.Tun.ExcludePackage = []string{"example.exclude"}
		cfg.Listeners = []map[string]any{
			{"type": "http", "name": "http"},
			{"type": "tun", "name": "tun"},
			{"type": "tproxy", "name": "tproxy"},
			{"type": "redir", "name": "redir"},
			{"type": "socks", "name": "socks"},
		}
		before := *cfg
		patchMishka(cfg)
		if fd == 0 {
			if !reflect.DeepEqual(*cfg, before) {
				t.Fatal("ROOT configuration changed")
			}
			continue
		}
		if cfg.Interface != "" || cfg.RoutingMark != 0 || cfg.ExternalControllerTLS != "" {
			t.Fatal("VPN inherited interface, mark, or TLS controller")
		}
		if cfg.Tun.CongestionController != "" || len(cfg.Tun.IncludePackage) != 0 || len(cfg.Tun.ExcludePackage) != 0 {
			t.Fatal("VPN retained unsupported TUN fields")
		}
		if len(cfg.Listeners) != 2 || cfg.Listeners[0]["type"] != "http" || cfg.Listeners[1]["type"] != "socks" {
			t.Fatalf("VPN listeners = %#v", cfg.Listeners)
		}
	}
}

func TestPrependDomesticDirectLeavesEmptyRulesAlone(t *testing.T) {
	got := prependDomesticDirectWith(nil, mishkaDomesticDirectRules)
	if len(got) != 0 {
		t.Fatalf("expected no rules injected into an empty rule list, got %v", got)
	}
}

func TestPrependDomesticDirectPutsRulesBeforeFallback(t *testing.T) {
	rules := []string{"GEOIP,Private,DIRECT", "MATCH,Proxy"}
	got := prependDomesticDirectWith(rules, mishkaDomesticDirectRules)

	// The injected block must be a prefix: anything after MATCH would never match.
	last := got[len(got)-1]
	if last != "MATCH,Proxy" {
		t.Fatalf("expected MATCH to stay last, got %q", last)
	}
	if !slices.Contains(got, "GEOSITE,cn,DIRECT") {
		t.Fatalf("expected GEOSITE,cn to be injected, got %v", got)
	}
	if idx := slices.Index(got, "GEOSITE,cn,DIRECT"); idx >= slices.Index(got, "MATCH,Proxy") {
		t.Fatalf("domestic rule must precede the MATCH fallback, got %v", got)
	}
}

func TestPrependDomesticDirectSkipsDuplicates(t *testing.T) {
	rules := []string{"GEOSITE,cn,DIRECT", "MATCH,Proxy"}
	got := prependDomesticDirectWith(rules, mishkaDomesticDirectRules)

	count := 0
	for _, rule := range got {
		if ruleKey(rule) == ruleKey("GEOSITE,cn,DIRECT") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one GEOSITE,cn,DIRECT, got %d in %v", count, got)
	}
}

func TestPrependDomesticDirectIgnoresDuplicateParameters(t *testing.T) {
	// A subscription rule carrying an extra parameter still expresses the same
	// routing decision, so the candidate must not be injected alongside it.
	rules := []string{"GEOIP,CN,DIRECT,no-resolve", "MATCH,Proxy"}
	got := prependDomesticDirectWith(rules, []string{"GEOIP,CN,DIRECT"})
	if len(got) != len(rules) {
		t.Fatalf("expected no duplicate injection, got %v", got)
	}
}

func TestRuleKeyIgnoresCaseAndTrailingParameters(t *testing.T) {
	cases := [][2]string{
		{"GEOSITE,cn,DIRECT", "geosite,CN,direct"},
		{"GEOIP,CN,DIRECT,no-resolve", "geoip,cn,DIRECT"},
		{"MATCH,Proxy", "match,proxy"},
		{"  GEOSITE,cn,DIRECT  ", "GEOSITE,cn,DIRECT"},
	}
	for _, c := range cases {
		if got, want := ruleKey(c[0]), ruleKey(c[1]); got != want {
			t.Errorf("ruleKey(%q)=%q, ruleKey(%q)=%q; want equal", c[0], got, c[1], want)
		}
	}
}
