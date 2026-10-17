//go:build mishka

package config

import (
	"slices"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	T "github.com/metacubex/mihomo/tunnel"
)

var (
	mishkaDefaultNameServers = []string{
		"223.5.5.5",
		"119.29.29.29",
		"8.8.4.4",
		"1.0.0.1",
	}
	mishkaDefaultFakeIPFilter = []string{
		// STUN
		"+.stun.*.*",
		"+.stun.*.*.*",
		"+.stun.*.*.*.*",
		"+.stun.*.*.*.*.*",
		// Google Voices
		"lens.l.google.com",
		// Nintendo Switch STUN
		"*.n.n.srv.nintendo.net",
		// PlayStation STUN
		"+.stun.playstation.net",
		// Xbox
		"xbox.*.*.microsoft.com",
		"*.*.xboxlive.com",
		// Microsoft Captive Portal
		"*.msftncsi.com",
		"*.msftconnecttest.com",
		// Bilibili CDN
		"*.mcdn.bilivideo.cn",
		// Windows default LAN workgroup
		"WORKGROUP",
	}
	mishkaDefaultFakeIPRange = "28.0.0.0/8"
)

func init() {
	mishkaPatch = patchMishka
}

// mishkaDomesticDirectRules are prepended to the subscription rules when
// --domestic-direct is set and the runtime mode is "rule".
//
// Only built-in targets (DIRECT / REJECT) are used: a rule whose target proxy or
// group is missing makes parseRules reject the whole configuration, and a
// subscription is free to name its groups anything. The data codes below must
// likewise exist in the shipped geodata — an unknown GEOSITE code is a fatal
// parse error, not a silently skipped rule — which is why geodata ships inside
// the APK instead of being fetched on demand.
//
// Private ranges come first so RFC1918 / CGNAT / link-local never reach a proxy
// on devices whose subscription lacks a private rule. The trailing REJECT covers
// the ad category that mihomo's bundled geosite ships but subscriptions rarely use.
var mishkaDomesticDirectRules = []string{
	"GEOSITE,private,DIRECT",
	"GEOSITE,cn,DIRECT",
	"GEOSITE,geolocation-cn,DIRECT",
	"GEOIP,private,DIRECT,no-resolve",
	"GEOIP,CN,DIRECT",
	"GEOSITE,category-ads-all,REJECT",
}

// prependDomesticDirect inserts the domestic-direct rules ahead of the
// subscription rules. Prepending (rather than appending) is required: a
// subscription almost always ends in MATCH / GEOIP,CN,PROXY, which would
// otherwise capture everything first and make the injected rules dead weight.
//
// Rules already present in the subscription are skipped, so a subscription that
// ships its own GEOSITE,cn,DIRECT does not end up with a duplicate.
func prependDomesticDirect(rules []string) []string {
	return prependDomesticDirectWith(rules, mishkaDomesticDirectRules)
}

// prependDomesticDirectWith is the testable core.
//
// It deliberately does NOT probe geodata: this runs inside Parse before
// ParseRawConfig has prepared the geodata directory, so a LoadGeoSiteMatcher
// probe fails unconditionally and would silently disable the whole feature.
// The cost of not probing is that a missing data code turns into a parse error;
// that is acceptable because geodata is shipped inside the APK (see
// MishkaApplication.extractGeoFiles) and the codes below are all part of the
// standard MetaCubeX build.
func prependDomesticDirectWith(rules []string, candidates []string) []string {
	if len(rules) == 0 {
		// No subscription rules at all: injecting domestic rules alone would leave a
		// half-configured routing table where everything else matches nothing. Leave
		// it untouched instead of pretending the config is complete.
		return rules
	}

	existing := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		existing[ruleKey(rule)] = struct{}{}
	}

	injected := make([]string, 0, len(candidates))
	for _, rule := range candidates {
		if _, ok := existing[ruleKey(rule)]; ok {
			continue
		}
		injected = append(injected, rule)
	}

	if len(injected) == 0 {
		return rules
	}
	return append(injected, rules...)
}

// ruleKey normalises a rule to the part that identifies it: TYPE,payload,target.
// Extra parameters (no-resolve etc.) are ignored so a subscription rule with the
// same routing effect is treated as a duplicate of the candidate.
func ruleKey(rule string) string {
	parts := strings.Split(strings.TrimSpace(rule), ",")
	if len(parts) < 3 {
		return strings.ToUpper(strings.Join(parts, ","))
	}
	return strings.ToUpper(parts[0] + "," + parts[1] + "," + parts[2])
}

// patchMishka adjusts the parsed RawConfig for Android usage:
//   - 未启用 DNS 时补 fake-ip 配置，否则 TUN 接管查询后无人应答。
//     AppendSystemDNS 把 system:// 加入主 nameserver 并发查询，并非失败后才回退。
//   - fd 模式只保留 Android 可用的 TUN 字段，并清掉会与 VPN fd 抢 TUN 的
//     Interface / RoutingMark / TLS 与 tun/tproxy/redir 入站。
func patchMishka(cfg *RawConfig) {
	// 国内直连规则：只在 rule 模式注入。global 模式下所有流量经选中出口、direct 模式全部直连，
	// 两者都不存在分流问题，注入只会污染规则列表；这两个模式也正是用户关掉该行为的开关。
	if DomesticDirect && cfg.Mode == T.Rule {
		cfg.Rule = prependDomesticDirect(cfg.Rule)
	}

	if !cfg.DNS.Enable {
		cfg.DNS = DefaultRawConfig().DNS
		cfg.DNS.Enable = true
		cfg.DNS.NameServer = mishkaDefaultNameServers
		cfg.DNS.EnhancedMode = C.DNSFakeIP
		cfg.DNS.FakeIPRange = mishkaDefaultFakeIPRange
		cfg.DNS.FakeIPFilter = mishkaDefaultFakeIPFilter
		cfg.ClashForAndroid.AppendSystemDNS = true
	}
	if cfg.ClashForAndroid.AppendSystemDNS && !slices.Contains(cfg.DNS.NameServer, "system://") && !slices.Contains(cfg.DNS.NameServer, "system") {
		cfg.DNS.NameServer = append(cfg.DNS.NameServer, "system://")
	}

	// ROOT 模式（fd == 0）走 mihomo TUN（netlink + tun.New()）路径。
	if cfg.Tun.FileDescriptor > 0 {
		cfg.Interface = ""
		cfg.RoutingMark = 0
		cfg.ExternalControllerTLS = ""
		cfg.Listeners = slices.DeleteFunc(cfg.Listeners, func(mapping map[string]any) bool {
			switch mapping["type"] {
			case "tun", "tproxy", "redir":
				return true
			default:
				return false
			}
		})
		// 白名单外的所有 RawTun 字段归零。
		cfg.Tun = RawTun{
			Enable:              cfg.Tun.Enable,
			Device:              cfg.Tun.Device,
			Stack:               cfg.Tun.Stack,
			DNSHijack:           cfg.Tun.DNSHijack,
			AutoRoute:           cfg.Tun.AutoRoute,
			AutoDetectInterface: cfg.Tun.AutoDetectInterface,
			Inet6Address:        cfg.Tun.Inet6Address,
			MTU:                 cfg.Tun.MTU,
			FileDescriptor:      cfg.Tun.FileDescriptor,
		}
	}
}
