package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	loginFailureWindow       = 10 * time.Minute
	loginIPBlockDuration     = 30 * time.Minute
	loginGroupBlockDuration  = 20 * time.Minute
	loginGlobalBlockDuration = time.Minute
	maxLoginFailures         = 5
	maxLoginAttempts         = 10000
	automaticSourceBan       = 30 * time.Minute
)

type loginLimit struct {
	Key      string
	Layer    string
	Failures int
	BlockFor time.Duration
}

type securityBlock struct {
	Address   string    `json:"address"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedBy string    `json:"createdBy"`
}

func accountFingerprint(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return hex.EncodeToString(sum[:6])
}

func loginLimits(identity ...string) []loginLimit {
	address := "unknown"
	username := ""
	if len(identity) > 0 && strings.TrimSpace(identity[0]) != "" {
		address = strings.TrimSpace(identity[0])
	}
	if len(identity) > 1 {
		username = identity[1]
	}
	if ip := net.ParseIP(address); ip != nil {
		address = ip.String()
	}
	limits := []loginLimit{{Key: "ip:" + address, Layer: "ip", Failures: maxLoginFailures, BlockFor: loginIPBlockDuration}}
	if subnet := loginSubnet(address); subnet != "" {
		limits = append(limits, loginLimit{Key: "subnet:" + subnet, Layer: "subnet", Failures: 20, BlockFor: loginGroupBlockDuration})
	}
	if strings.TrimSpace(username) != "" {
		limits = append(limits, loginLimit{Key: "account:" + accountFingerprint(username), Layer: "account", Failures: 12, BlockFor: loginGroupBlockDuration})
	}
	limits = append(limits, loginLimit{Key: "global", Layer: "global", Failures: 250, BlockFor: loginGlobalBlockDuration})
	return limits
}

func loginSubnet(address string) string {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return ""
	}
	bits := 64
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		bits = 24
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(bits, len(ip)*8)), Mask: net.CIDRMask(bits, len(ip)*8)}).String()
}

func (a *app) loginRetryAfter(identity ...string) int {
	retry, _ := a.loginBlockStatus(identity...)
	return retry
}

func (a *app) loginBlockStatus(identity ...string) (int, string) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]loginAttempt{}
	}
	maxRetry, blockedLayer := 0, ""
	for _, limit := range loginLimits(identity...) {
		attempt, ok := a.loginAttempts[limit.Key]
		if !ok {
			continue
		}
		if !attempt.BlockedUntil.IsZero() && now.Before(attempt.BlockedUntil) {
			retry := max(1, int(time.Until(attempt.BlockedUntil).Seconds()))
			if retry > maxRetry {
				maxRetry, blockedLayer = retry, limit.Layer
			}
			continue
		}
		if now.Sub(attempt.LastFailure) > loginFailureWindow || (!attempt.BlockedUntil.IsZero() && !now.Before(attempt.BlockedUntil)) {
			delete(a.loginAttempts, limit.Key)
		}
	}
	return maxRetry, blockedLayer
}

func (a *app) recordLoginFailure(identity ...string) (int, string) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]loginAttempt{}
	}
	a.pruneLoginAttemptsLocked(now)
	maxRetry, blockedLayer := 0, ""
	for _, limit := range loginLimits(identity...) {
		if _, exists := a.loginAttempts[limit.Key]; !exists && len(a.loginAttempts) >= maxLoginAttempts {
			a.evictOldestLoginAttemptLocked()
		}
		attempt := a.loginAttempts[limit.Key]
		if now.Sub(attempt.LastFailure) > loginFailureWindow {
			attempt.Failures = 0
		}
		attempt.Failures++
		attempt.LastFailure = now
		if attempt.Failures >= limit.Failures {
			attempt.BlockedUntil = now.Add(limit.BlockFor)
			retry := max(1, int(limit.BlockFor.Seconds()))
			if retry > maxRetry {
				maxRetry, blockedLayer = retry, limit.Layer
			}
		}
		a.loginAttempts[limit.Key] = attempt
	}
	return maxRetry, blockedLayer
}

func (a *app) clearLoginFailures(identity ...string) {
	limits := loginLimits(identity...)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, limit := range limits {
		if limit.Layer == "ip" || limit.Layer == "account" {
			delete(a.loginAttempts, limit.Key)
		}
	}
}

func (a *app) pruneLoginAttemptsLocked(now time.Time) {
	if len(a.loginAttempts) < maxLoginAttempts {
		return
	}
	for key, attempt := range a.loginAttempts {
		if now.Sub(attempt.LastFailure) > loginFailureWindow && now.After(attempt.BlockedUntil) {
			delete(a.loginAttempts, key)
		}
	}
}

func (a *app) evictOldestLoginAttemptLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, attempt := range a.loginAttempts {
		if oldestKey == "" || attempt.LastFailure.Before(oldest) {
			oldestKey, oldest = key, attempt.LastFailure
		}
	}
	delete(a.loginAttempts, oldestKey)
}

func isPublicLoginSource(address string) bool {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	_, carrierNAT, _ := net.ParseCIDR("100.64.0.0/10")
	return carrierNAT == nil || !carrierNAT.Contains(ip)
}

func canonicalBlockAddress(address string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return "", errors.New("封禁来源必须是非回环的具体 IPv4 或 IPv6 地址")
	}
	return ip.String(), nil
}

func (a *app) securityBlockPath() string {
	return filepath.Join(a.dataDir, "blocked-sources.json")
}

func (a *app) loadSecurityBlocks() []securityBlock {
	now := time.Now()
	a.securityMu.Lock()
	defer a.securityMu.Unlock()
	blocks, changed := a.loadSecurityBlocksLocked(now)
	if changed {
		_ = a.saveSecurityBlocksLocked(blocks)
	}
	return blocks
}

func (a *app) loadSecurityBlocksLocked(now time.Time) ([]securityBlock, bool) {
	var stored []securityBlock
	data, err := os.ReadFile(a.securityBlockPath())
	if err == nil {
		_ = json.Unmarshal(data, &stored)
	}
	blocks := make([]securityBlock, 0, len(stored))
	changed := false
	seen := map[string]bool{}
	for _, block := range stored {
		address, parseErr := canonicalBlockAddress(block.Address)
		if parseErr != nil || !block.ExpiresAt.After(now) || seen[address] {
			changed = true
			continue
		}
		if address != block.Address {
			block.Address = address
			changed = true
		}
		seen[address] = true
		blocks = append(blocks, block)
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].ExpiresAt.Before(blocks[j].ExpiresAt) })
	return blocks, changed
}

func (a *app) saveSecurityBlocksLocked(blocks []securityBlock) error {
	data, err := json.MarshalIndent(blocks, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(a.securityBlockPath(), data, 0600)
}

func (a *app) replaceSecurityBlocks(blocks []securityBlock) error {
	a.securityMu.Lock()
	defer a.securityMu.Unlock()
	return a.saveSecurityBlocksLocked(blocks)
}

func (a *app) upsertSecurityBlock(address, reason string, duration time.Duration, createdBy string) (securityBlock, bool, error) {
	address, err := canonicalBlockAddress(address)
	if err != nil {
		return securityBlock{}, false, err
	}
	reason = cleanNote(reason)
	if len([]rune(reason)) < 3 {
		return securityBlock{}, false, errors.New("封禁原因至少填写 3 个字符")
	}
	if duration < time.Minute || duration > 30*24*time.Hour {
		return securityBlock{}, false, errors.New("封禁时长必须在 1 分钟到 30 天之间")
	}
	if strings.TrimSpace(createdBy) == "" {
		createdBy = "system"
	}
	now := time.Now()
	block := securityBlock{Address: address, Reason: reason, CreatedAt: now, ExpiresAt: now.Add(duration), CreatedBy: createdBy}
	a.securityMu.Lock()
	blocks, _ := a.loadSecurityBlocksLocked(now)
	created := true
	for i := range blocks {
		if blocks[i].Address == address {
			created = false
			if block.ExpiresAt.After(blocks[i].ExpiresAt) {
				blocks[i].ExpiresAt = block.ExpiresAt
			}
			blocks[i].Reason = reason
			blocks[i].CreatedBy = createdBy
			block = blocks[i]
			break
		}
	}
	if created {
		blocks = append(blocks, block)
	}
	err = a.saveSecurityBlocksLocked(blocks)
	a.securityMu.Unlock()
	if err != nil {
		return securityBlock{}, false, err
	}
	return block, created, nil
}

func (a *app) removeSecurityBlock(address string) (securityBlock, error) {
	address, err := canonicalBlockAddress(address)
	if err != nil {
		return securityBlock{}, err
	}
	a.securityMu.Lock()
	blocks, _ := a.loadSecurityBlocksLocked(time.Now())
	filtered := make([]securityBlock, 0, len(blocks))
	var removed securityBlock
	for _, block := range blocks {
		if block.Address == address {
			removed = block
			continue
		}
		filtered = append(filtered, block)
	}
	if removed.Address == "" {
		a.securityMu.Unlock()
		return securityBlock{}, os.ErrNotExist
	}
	err = a.saveSecurityBlocksLocked(filtered)
	a.securityMu.Unlock()
	if err != nil {
		return securityBlock{}, err
	}
	return removed, nil
}

func (a *app) refreshFirewallBlocks() {
	if runtime.GOOS != "linux" || !commandExists("nft") || !nftTableExists() {
		return
	}
	a.firewallActionMu.Lock()
	defer a.firewallActionMu.Unlock()
	if err := a.applyFirewallRules(a.loadFirewallRules()); err != nil {
		log.Printf("SECURITY firewall_refresh_failed error=%q", truncate(err.Error(), 300))
	}
}

func (a *app) autoEnableFirewall() {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("TAF_FIREWALL_AUTO_ENABLE") == "0" {
		return
	}
	if !commandExists("nft") {
		log.Printf("SECURITY firewall_auto_enable_skipped reason=nft_not_installed")
		return
	}
	if err := a.applyFirewallRules(a.loadFirewallRules()); err != nil {
		log.Printf("SECURITY firewall_auto_enable_failed error=%q", truncate(err.Error(), 300))
		a.auditWithIP("firewall.auto_enable", "inet tryallfun", false, err.Error(), "system")
		return
	}
	log.Printf("SECURITY firewall_auto_enabled policy=drop")
	a.auditWithIP("firewall.auto_enable", "inet tryallfun", true, "default deny and intrusion protection loaded", "system")
}

func (a *app) firewallCLI(args []string) error {
	a.firewallActionMu.Lock()
	defer a.firewallActionMu.Unlock()
	if len(args) == 1 && args[0] == "list" {
		data, err := json.MarshalIndent(map[string]any{"rules": a.loadFirewallRules(), "blocks": a.loadSecurityBlocks()}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	if len(args) < 4 || len(args) > 5 || args[0] != "open" {
		return errors.New("用法: kunpanel firewall open <tcp|udp> <端口> <用途备注> [来源CIDR]，或 kunpanel firewall list")
	}
	port, err := strconv.Atoi(args[2])
	if err != nil {
		return errors.New("端口必须是 1 到 65535 的整数")
	}
	source := "0.0.0.0/0"
	if len(args) > 4 {
		source = strings.TrimSpace(args[4])
	}
	destination := "0.0.0.0/0"
	if strings.Contains(source, ":") {
		destination = "::/0"
	}
	rule := firewallRule{
		ID: randomToken(8), Direction: "in", Port: port, Protocol: strings.ToLower(args[1]),
		Source: source, Destination: destination, Action: "allow", Note: cleanNote(args[3]),
		CreatedAt: time.Now(), CreatedBy: "cli:root",
	}
	if err := validateNewFirewallRule(rule); err != nil {
		return err
	}
	if !commandExists("nft") {
		return errors.New("未安装 nftables，请先安装 nftables 后再开放端口")
	}
	rules := a.loadFirewallRules()
	for _, existing := range rules {
		if sameFirewallRule(existing, rule) {
			return errors.New("相同的防火墙规则已经存在")
		}
	}
	rules = append(rules, rule)
	if err := a.applyFirewallRules(rules); err != nil {
		return err
	}
	a.auditWithIP("firewall.port_open", fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), true, fmt.Sprintf("source=%s purpose=%s opened=%s actor=cli:root", rule.Source, rule.Note, rule.CreatedAt.Format(time.RFC3339)), "system")
	fmt.Printf("已开放 %s/%d，用途：%s，来源：%s\n", rule.Protocol, rule.Port, rule.Note, rule.Source)
	return nil
}

func (a *app) autoBlockLoginSource(address, layer string) {
	if !isPublicLoginSource(address) || layer == "global" || layer == "" || isActiveSSHPeer(address) {
		return
	}
	reason := fmt.Sprintf("登录爆破自动防护（%s）", layer)
	block, created, err := a.upsertSecurityBlock(address, reason, automaticSourceBan, "automatic")
	if err != nil {
		log.Printf("SECURITY auth_ban_failed client=%s layer=%s error=%q", address, layer, truncate(err.Error(), 200))
		return
	}
	if created {
		a.auditWithIP("security.source_block", block.Address, true, fmt.Sprintf("reason=%s expires=%s actor=automatic", block.Reason, block.ExpiresAt.Format(time.RFC3339)), address)
		log.Printf("SECURITY source_block client=%s layer=%s expires=%s", block.Address, layer, block.ExpiresAt.Format(time.RFC3339))
	}
	a.refreshFirewallBlocks()
}

func isActiveSSHPeer(address string) bool {
	if runtime.GOOS != "linux" || !commandExists("ss") {
		return false
	}
	out, err := runCommand(5*time.Second, "ss", "-Htn", "state", "established", "sport", "=", fmt.Sprintf(":%d", sshPort()))
	if err != nil {
		return false
	}
	return sshPeerPresent(out, address)
}

func sshPeerPresent(output, address string) bool {
	want := net.ParseIP(address)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host, _, splitErr := net.SplitHostPort(fields[len(fields)-1])
		got := net.ParseIP(strings.Trim(host, "[]"))
		if splitErr == nil && got != nil && want != nil && got.Equal(want) {
			return true
		}
	}
	return false
}

func (a *app) auditWithIP(action, target string, success bool, detail, ip string) {
	target, detail = safeAuditFields(action, target, detail)
	entry := auditEntry{Time: time.Now(), Action: action, Target: target, Success: success, Detail: detail, IP: ip}
	data, _ := json.Marshal(entry)
	a.appendAuditLine(filepath.Join(a.dataDir, "audit.jsonl"), append(data, '\n'))
}
