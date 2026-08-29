package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoginSubnetUsesIPv4Slash24AndIPv6Slash64(t *testing.T) {
	if got := loginSubnet("203.0.113.47"); got != "203.0.113.0/24" {
		t.Fatalf("IPv4 subnet = %q", got)
	}
	if got := loginSubnet("2001:db8:1234:5678:abcd::1"); got != "2001:db8:1234:5678::/64" {
		t.Fatalf("IPv6 subnet = %q", got)
	}
}

func TestDistributedAccountPasswordSprayIsBlocked(t *testing.T) {
	a := &app{loginAttempts: map[string]loginAttempt{}}
	var layer string
	for i := 1; i <= 12; i++ {
		_, layer = a.recordLoginFailure(fmt.Sprintf("8.8.%d.%d", i, i), "owner")
	}
	if layer != "account" {
		t.Fatalf("blocking layer = %q, want account", layer)
	}
	if retry, gotLayer := a.loginBlockStatus("9.9.9.9", "owner"); retry <= 0 || gotLayer != "account" {
		t.Fatalf("distributed account block = retry %d layer %q", retry, gotLayer)
	}
}

func TestPreflightChecksPreserveFailureEvidenceUntilThreshold(t *testing.T) {
	a := &app{loginAttempts: map[string]loginAttempt{}}
	for i := 0; i < maxLoginFailures; i++ {
		if retry, layer := a.loginBlockStatus("8.8.8.8", "owner"); retry != 0 || layer != "" {
			t.Fatalf("request %d blocked too early: retry=%d layer=%q", i+1, retry, layer)
		}
		a.recordLoginFailure("8.8.8.8", "owner")
	}
	if retry, layer := a.loginBlockStatus("8.8.8.8", "owner"); retry <= 0 || layer != "ip" {
		t.Fatalf("threshold did not block source: retry=%d layer=%q", retry, layer)
	}
}

func TestRotatingSubnetPasswordAttackIsBlocked(t *testing.T) {
	a := &app{loginAttempts: map[string]loginAttempt{}}
	var layer string
	for i := 1; i <= 20; i++ {
		_, layer = a.recordLoginFailure(fmt.Sprintf("8.8.4.%d", i), fmt.Sprintf("user-%d", i))
	}
	if layer != "subnet" {
		t.Fatalf("blocking layer = %q, want subnet", layer)
	}
	if retry, gotLayer := a.loginBlockStatus("8.8.4.200", "another"); retry <= 0 || gotLayer != "subnet" {
		t.Fatalf("subnet block = retry %d layer %q", retry, gotLayer)
	}
}

func TestHighVolumeDistributedLoginFailuresTriggerGlobalBrake(t *testing.T) {
	a := &app{loginAttempts: map[string]loginAttempt{}}
	var layer string
	for i := 0; i < 250; i++ {
		_, layer = a.recordLoginFailure(fmt.Sprintf("11.%d.0.1", i), fmt.Sprintf("random-%d", i))
	}
	if layer != "global" {
		t.Fatalf("blocking layer = %q, want global", layer)
	}
	if retry, gotLayer := a.loginBlockStatus("12.0.0.1", "new-account"); retry <= 0 || gotLayer != "global" {
		t.Fatalf("global brake = retry %d layer %q", retry, gotLayer)
	}
}

func TestSuccessfulLoginDoesNotEraseSubnetOrGlobalEvidence(t *testing.T) {
	a := &app{loginAttempts: map[string]loginAttempt{}}
	a.recordLoginFailure("8.8.8.8", "owner")
	a.clearLoginFailures("8.8.8.8", "owner")
	if _, ok := a.loginAttempts["ip:8.8.8.8"]; ok {
		t.Fatal("IP evidence was not cleared after a successful login")
	}
	if _, ok := a.loginAttempts["account:"+accountFingerprint("owner")]; ok {
		t.Fatal("account evidence was not cleared after a successful login")
	}
	if _, ok := a.loginAttempts["subnet:8.8.8.0/24"]; !ok {
		t.Fatal("subnet evidence was erased by a successful login")
	}
	if _, ok := a.loginAttempts["global"]; !ok {
		t.Fatal("global evidence was erased by a successful login")
	}
}

func TestOnlyPublicSourcesAreAutomaticallyBanned(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.4", "172.16.2.3", "192.168.1.4", "100.64.0.1", "::1", "fd00::1"} {
		if isPublicLoginSource(address) {
			t.Fatalf("private or local source considered public: %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !isPublicLoginSource(address) {
			t.Fatalf("public source was not eligible for automatic ban: %s", address)
		}
	}
}

func TestActiveSSHPeerParsing(t *testing.T) {
	output := "0 0 192.0.2.10:43871 198.51.100.23:25850\nESTAB 0 0 [2001:db8::1]:43871 [2001:db8::2]:51300\n"
	if !sshPeerPresent(output, "198.51.100.23") || !sshPeerPresent(output, "2001:db8::2") {
		t.Fatal("active SSH peer was not recognized")
	}
	if sshPeerPresent(output, "8.8.8.8") {
		t.Fatal("unrelated source was recognized as an active SSH peer")
	}
}

func TestSecurityBlocksPersistAndExpiredEntriesArePruned(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	block, created, err := a.upsertSecurityBlock("8.8.8.8", "manual test block", time.Hour, "owner")
	if err != nil || !created || block.CreatedBy != "owner" {
		t.Fatalf("persist block = %#v created=%v err=%v", block, created, err)
	}
	expired := securityBlock{Address: "1.1.1.1", Reason: "expired test", CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour), CreatedBy: "test"}
	data, _ := json.Marshal([]securityBlock{block, expired})
	if err := os.WriteFile(a.securityBlockPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	blocks := a.loadSecurityBlocks()
	if len(blocks) != 1 || blocks[0].Address != "8.8.8.8" {
		t.Fatalf("active blocks = %#v", blocks)
	}
}

func TestDefaultFirewallOnlyAllowsCurrentSSHPort(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	rules := a.loadFirewallRules()
	if len(rules) != 2 {
		t.Fatalf("default firewall rule count = %d, want IPv4 and IPv6 SSH", len(rules))
	}
	for _, rule := range rules {
		if rule.Port != sshPort() || rule.Protocol != "tcp" || rule.Action != "allow" || rule.CreatedBy != "system" || rule.CreatedAt.IsZero() {
			t.Fatalf("unexpected default rule: %#v", rule)
		}
	}
	data, err := os.ReadFile(filepath.Join(a.dataDir, "firewall.json"))
	if err != nil || strings.Contains(string(data), `"port": 80`) || strings.Contains(string(data), `"port": 443`) {
		t.Fatalf("default firewall opened web ports: %s err=%v", data, err)
	}
}

func TestNewInboundAllowRequiresPortAndPurpose(t *testing.T) {
	base := firewallRule{Direction: "in", Protocol: "tcp", Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow"}
	if err := validateNewFirewallRule(base); err == nil {
		t.Fatal("portless inbound allow was accepted")
	}
	base.Port = 443
	base.Note = "x"
	if err := validateNewFirewallRule(base); err == nil {
		t.Fatal("inbound allow without a useful purpose was accepted")
	}
	base.Note = "KunPanel HTTPS"
	if err := validateNewFirewallRule(base); err != nil {
		t.Fatalf("valid inbound allow rejected: %v", err)
	}
}

func TestFirewallConfigContainsScanRateAndDynamicBlockProtection(t *testing.T) {
	now := time.Now()
	config := buildFirewallConfig([]firewallRule{{Direction: "in", Protocol: "tcp", Port: 22, Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow", Note: "SSH"}}, []securityBlock{{Address: "8.8.8.8", ExpiresAt: now.Add(time.Hour)}}, now)
	for _, want := range []string{
		"policy drop", "ct state invalid counter drop", "@blocked_v4", "8.8.8.8 timeout",
		"tcp flags & (fin|syn|rst|psh|ack|urg) == 0", "meter syn_rate_v4", "meter syn_rate_v6",
		"meter udp_rate_v4", "ct state new limit rate over", "meta nfproto ipv4 tcp dport 22 accept",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("firewall config missing %q:\n%s", want, config)
		}
	}
}

func TestFirewallRulesAreRestrictedToTheirAddressFamily(t *testing.T) {
	config := buildFirewallConfig([]firewallRule{
		{Direction: "in", Protocol: "tcp", Port: 443, Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow", Note: "IPv4 HTTPS"},
		{Direction: "in", Protocol: "tcp", Port: 8443, Source: "::/0", Destination: "::/0", Action: "allow", Note: "IPv6 HTTPS"},
	}, nil, time.Now())
	if !strings.Contains(config, "meta nfproto ipv4 tcp dport 443 accept") || !strings.Contains(config, "meta nfproto ipv6 tcp dport 8443 accept") {
		t.Fatalf("address-family constraints missing:\n%s", config)
	}
}

func TestInvalidPersistedFirewallRulesFallBackToSSH(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	data := []byte(`[{"id":"unsafe","direction":"in","port":443,"protocol":"tcp;flush ruleset","source":"0.0.0.0/0","destination":"0.0.0.0/0","action":"allow","note":"unsafe"}]`)
	if err := os.WriteFile(filepath.Join(a.dataDir, "firewall.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	rules := a.loadFirewallRules()
	if len(rules) != 2 {
		t.Fatalf("invalid persisted rule was not replaced by SSH defaults: %#v", rules)
	}
	for _, rule := range rules {
		if rule.Port != sshPort() || rule.Protocol != "tcp" || rule.Action != "allow" {
			t.Fatalf("unexpected fallback rule: %#v", rule)
		}
	}
}

func TestGeneratedFirewallConfigPassesNftCheckWhenAvailable(t *testing.T) {
	if os.Getenv("TAF_NFT_SYNTAX_CHECK") != "1" || runtime.GOOS != "linux" || !commandExists("nft") {
		t.Skip("nft syntax check requires Linux with nftables installed")
	}
	now := time.Now()
	config := buildFirewallConfig([]firewallRule{
		{Direction: "in", Protocol: "tcp", Port: 22, Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow", Note: "SSH IPv4"},
		{Direction: "in", Protocol: "tcp", Port: 22, Source: "::/0", Destination: "::/0", Action: "allow", Note: "SSH IPv6"},
	}, []securityBlock{
		{Address: "8.8.8.8", ExpiresAt: now.Add(time.Hour)},
		{Address: "2606:4700:4700::1111", ExpiresAt: now.Add(time.Hour)},
	}, now)
	path := filepath.Join(t.TempDir(), "kunpanel.nft")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := runCommand(15*time.Second, "nft", "-c", "-f", path); err != nil {
		t.Fatalf("nft rejected generated config: %s", outOrErr(output, err))
	}
}
