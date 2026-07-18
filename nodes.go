package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type managedNode struct {
	Alias   string    `json:"alias"`
	Host    string    `json:"host"`
	User    string    `json:"user"`
	Port    int       `json:"port"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

var nodeHostRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)$`)

func (a *app) nodesDir() string           { return filepath.Join(a.dataDir, "nodes") }
func (a *app) nodesPath() string          { return filepath.Join(a.nodesDir(), "nodes.json") }
func (a *app) nodeSSHDir() string         { return filepath.Join(a.dataDir, "ssh") }
func (a *app) nodeKeyPath() string        { return filepath.Join(a.nodeSSHDir(), "id_ed25519") }
func (a *app) nodePublicKeyPath() string  { return a.nodeKeyPath() + ".pub" }
func (a *app) nodeKnownHostsPath() string { return filepath.Join(a.nodeSSHDir(), "known_hosts") }

func (a *app) handleNodes(w http.ResponseWriter, r *http.Request) {
	if !a.requireRole(w, r, "admin", "operator") {
		return
	}
	if r.Method == http.MethodGet {
		items, err := a.loadNodes()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		publicKey := ""
		if b, err := os.ReadFile(a.nodePublicKeyPath()); err == nil {
			publicKey = strings.TrimSpace(string(b))
		}
		writeJSON(w, 200, map[string]any{
			"nodes": items, "keyReady": fileExists(a.nodeKeyPath()) && publicKey != "", "publicKey": publicKey,
			"passwordBootstrapReady": commandExists("sshpass") && commandExists("ssh-copy-id"),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Action, Alias, Host, User, Password, Command, Confirm string
		Port, NewPort                                         int
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if oneOf(in.Action, "probe", "probe-all", "info") {
		a.handleNodeReadAction(w, r, in.Action, in.Alias)
		return
	}
	if !a.requireRole(w, r, "admin") || !a.requireMaintenance(w, r) {
		return
	}
	switch in.Action {
	case "init-key":
		if err := a.ensureNodeKey(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		publicKey, _ := os.ReadFile(a.nodePublicKeyPath())
		a.audit(r, "node.key.init", a.nodeKeyPath(), true, "ed25519 key ready")
		writeJSON(w, 200, map[string]any{"ok": true, "publicKey": strings.TrimSpace(string(publicKey))})
	case "add":
		node := managedNode{Alias: strings.TrimSpace(in.Alias), Host: strings.TrimSpace(in.Host), User: strings.TrimSpace(in.User), Port: in.Port}
		if node.User == "" {
			node.User = "root"
		}
		if node.Port == 0 {
			node.Port = 22
		}
		if err := validateNode(node); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := a.upsertNode(node); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		stored, err := a.resolveNode(node.Alias)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		node = stored
		if in.Password != "" {
			password := in.Password
			j := a.startNodeJob("下发节点公钥 "+node.Alias, r, func() (string, error) {
				return "", a.syncNodeKey(node, password)
			})
			a.audit(r, "node.add", node.Alias, true, node.User+"@"+node.Host+":"+strconv.Itoa(node.Port))
			writeJSON(w, 202, map[string]any{"node": node, "job": j})
			return
		}
		a.audit(r, "node.add", node.Alias, true, node.User+"@"+node.Host+":"+strconv.Itoa(node.Port))
		writeJSON(w, 201, node)
	case "delete":
		if in.Confirm != "DELETE "+in.Alias {
			writeJSON(w, 400, map[string]string{"error": "删除确认文本不正确"})
			return
		}
		if err := a.deleteNode(in.Alias); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "node.delete", in.Alias, true, "node removed")
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "sync-key":
		node, err := a.resolveNode(in.Alias)
		if err != nil || in.Password == "" {
			writeJSON(w, 400, map[string]string{"error": "节点不存在或一次性密码为空"})
			return
		}
		password := in.Password
		j := a.startNodeJob("下发节点公钥 "+node.Alias, r, func() (string, error) {
			return "", a.syncNodeKey(node, password)
		})
		writeJSON(w, 202, j)
	case "lock":
		node, err := a.resolveNode(in.Alias)
		if err != nil || in.Confirm != "LOCK "+node.Alias {
			writeJSON(w, 400, map[string]string{"error": "节点不存在或确认文本不正确"})
			return
		}
		j := a.startNodeJob("关闭节点密码登录 "+node.Alias, r, func() (string, error) { return a.lockNodePassword(node) })
		writeJSON(w, 202, j)
	case "port":
		node, err := a.resolveNode(in.Alias)
		if err != nil || in.NewPort < 1 || in.NewPort > 65535 || in.NewPort == node.Port || in.Confirm != "CHANGE PORT "+node.Alias {
			writeJSON(w, 400, map[string]string{"error": "节点或新端口无效"})
			return
		}
		newPort := in.NewPort
		j := a.startNodeJob("迁移节点 SSH 端口 "+node.Alias, r, func() (string, error) { return a.changeNodePort(node, newPort) })
		writeJSON(w, 202, j)
	case "run":
		node, err := a.resolveNode(in.Alias)
		in.Command = strings.TrimSpace(in.Command)
		if err != nil || in.Command == "" || len(in.Command) > 4096 || in.Confirm != "EXECUTE "+node.Alias {
			writeJSON(w, 400, map[string]string{"error": "节点、命令或确认文本无效"})
			return
		}
		command := in.Command
		j := a.startNodeJob("执行节点命令 "+node.Alias, r, func() (string, error) {
			return a.runNodeScript(node, node.Port, command+"\n", 2*time.Minute)
		})
		writeJSON(w, 202, j)
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的节点操作"})
	}
}

func (a *app) handleNodeReadAction(w http.ResponseWriter, _ *http.Request, action, alias string) {
	if action == "probe-all" {
		items, err := a.loadNodes()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		result := make([]map[string]any, len(items))
		var wg sync.WaitGroup
		limit := make(chan struct{}, 10)
		for i, node := range items {
			wg.Add(1)
			go func(index int, current managedNode) {
				defer wg.Done()
				limit <- struct{}{}
				defer func() { <-limit }()
				start := time.Now()
				err := a.probeNode(current, current.Port)
				result[index] = map[string]any{"alias": current.Alias, "online": err == nil, "latencyMs": time.Since(start).Milliseconds(), "error": errorString(err)}
			}(i, node)
		}
		wg.Wait()
		writeJSON(w, 200, result)
		return
	}
	node, err := a.resolveNode(alias)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if action == "probe" {
		start := time.Now()
		err := a.probeNode(node, node.Port)
		writeJSON(w, 200, map[string]any{"alias": node.Alias, "online": err == nil, "latencyMs": time.Since(start).Milliseconds(), "error": errorString(err)})
		return
	}
	script := `set -eu
echo "Hostname : $(hostname)"
echo "OS       : $(. /etc/os-release 2>/dev/null && echo ${PRETTY_NAME:-unknown} || uname -s)"
echo "Kernel   : $(uname -r)"
echo "CPU      : $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown) cores"
echo "Memory   : $(free -h 2>/dev/null | awk '/^Mem:/{print $2 " total, " $3 " used"}' || echo unknown)"
echo "Disk     : $(df -h / | awk 'NR==2{print $2 " total, " $3 " used, " $5 " usage"}')"
echo "Uptime   : $(uptime -p 2>/dev/null || uptime)"
echo "Ports    : $(ss -lntupH 2>/dev/null | wc -l) listening"
`
	out, err := a.runNodeScript(node, node.Port, script, 20*time.Second)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]any{"node": node, "output": out})
}

func validateNode(node managedNode) error {
	if !safeNameRE.MatchString(node.Alias) || !safeNameRE.MatchString(node.User) || node.Port < 1 || node.Port > 65535 {
		return errors.New("节点别名、用户或端口无效")
	}
	if net.ParseIP(node.Host) == nil && !nodeHostRE.MatchString(node.Host) {
		return errors.New("节点主机名或 IP 无效")
	}
	return nil
}

func (a *app) loadNodes() ([]managedNode, error) {
	a.nodeMu.RLock()
	defer a.nodeMu.RUnlock()
	return a.loadNodesUnlocked()
}

func (a *app) loadNodesUnlocked() ([]managedNode, error) {
	b, err := os.ReadFile(a.nodesPath())
	if errors.Is(err, os.ErrNotExist) {
		return []managedNode{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []managedNode
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	if len(items) > 100 {
		return nil, errors.New("节点数量超过 100 个上限")
	}
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Alias) < strings.ToLower(items[j].Alias) })
	return items, nil
}

func (a *app) saveNodes(items []managedNode) error {
	a.nodeMu.Lock()
	defer a.nodeMu.Unlock()
	return a.saveNodesUnlocked(items)
}

func (a *app) saveNodesUnlocked(items []managedNode) error {
	if err := os.MkdirAll(a.nodesDir(), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(a.nodesPath(), b, 0600)
}

func (a *app) upsertNode(node managedNode) error {
	a.nodeMu.Lock()
	defer a.nodeMu.Unlock()
	items, err := a.loadNodesUnlocked()
	if err != nil {
		return err
	}
	now := time.Now()
	node.Updated = now
	for i := range items {
		if strings.EqualFold(items[i].Alias, node.Alias) {
			node.Created = items[i].Created
			items[i] = node
			return a.saveNodesUnlocked(items)
		}
	}
	if len(items) >= 100 {
		return errors.New("节点数量已达到 100 个上限")
	}
	node.Created = now
	return a.saveNodesUnlocked(append(items, node))
}

func (a *app) deleteNode(alias string) error {
	a.nodeMu.Lock()
	defer a.nodeMu.Unlock()
	items, err := a.loadNodesUnlocked()
	if err != nil {
		return err
	}
	out := items[:0]
	found := false
	for _, node := range items {
		if strings.EqualFold(node.Alias, alias) {
			found = true
			continue
		}
		out = append(out, node)
	}
	if !found {
		return errors.New("节点不存在")
	}
	return a.saveNodesUnlocked(out)
}

func (a *app) resolveNode(alias string) (managedNode, error) {
	items, err := a.loadNodes()
	if err != nil {
		return managedNode{}, err
	}
	alias = strings.ToLower(strings.TrimSpace(alias))
	if alias == "" {
		return managedNode{}, errors.New("节点别名不能为空")
	}
	var matches []managedNode
	for _, node := range items {
		name := strings.ToLower(node.Alias)
		if name == alias {
			return node, nil
		}
		if strings.HasPrefix(name, alias) {
			matches = append(matches, node)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return managedNode{}, errors.New("节点别名匹配不唯一")
	}
	return managedNode{}, errors.New("节点不存在")
}

func (a *app) ensureNodeKey() error {
	if err := os.MkdirAll(a.nodeSSHDir(), 0700); err != nil {
		return err
	}
	if fileExists(a.nodeKeyPath()) {
		_ = os.Chmod(a.nodeKeyPath(), 0600)
		if !fileExists(a.nodePublicKeyPath()) {
			out, err := runCommand(15*time.Second, "ssh-keygen", "-y", "-f", a.nodeKeyPath())
			if err != nil {
				return errors.New(outOrErr(out, err))
			}
			return atomicWrite(a.nodePublicKeyPath(), []byte(strings.TrimSpace(out)+"\n"), 0644)
		}
		return nil
	}
	out, err := runCommand(30*time.Second, "ssh-keygen", "-t", "ed25519", "-f", a.nodeKeyPath(), "-N", "", "-C", "kunpanel-vps")
	if err != nil {
		return errors.New(outOrErr(out, err))
	}
	_ = os.Chmod(a.nodeKeyPath(), 0600)
	_ = os.Chmod(a.nodePublicKeyPath(), 0644)
	return nil
}

func (a *app) nodeSSHArgs(node managedNode, port int) []string {
	return []string{
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "UserKnownHostsFile=" + a.nodeKnownHostsPath(),
		"-i", a.nodeKeyPath(), "-p", strconv.Itoa(port), node.User + "@" + node.Host,
	}
}

func (a *app) probeNode(node managedNode, port int) error {
	if err := a.ensureNodeKey(); err != nil {
		return err
	}
	args := append(a.nodeSSHArgs(node, port), "true")
	_, err := runCommand(15*time.Second, "ssh", args...)
	return err
}

func (a *app) runNodeScript(node managedNode, port int, script string, timeout time.Duration, scriptArgs ...string) (string, error) {
	if err := a.ensureNodeKey(); err != nil {
		return "", err
	}
	args := append(a.nodeSSHArgs(node, port), "bash", "-s", "--")
	args = append(args, scriptArgs...)
	return runCommandEnvInput(timeout, script, nil, "ssh", args...)
}

func (a *app) syncNodeKey(node managedNode, password string) error {
	if err := a.ensureNodeKey(); err != nil {
		return err
	}
	if !commandExists("sshpass") || !commandExists("ssh-copy-id") {
		return errors.New("服务器需要先安装 sshpass 与 openssh-client")
	}
	if len(password) > 1024 || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("一次性密码无效")
	}
	args := []string{"-e", "ssh-copy-id", "-i", a.nodePublicKeyPath(), "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + a.nodeKnownHostsPath(), "-p", strconv.Itoa(node.Port), node.User + "@" + node.Host}
	out, err := runCommandEnvInput(45*time.Second, "", []string{"SSHPASS=" + password}, "sshpass", args...)
	if err != nil {
		return errors.New(outOrErr(out, err))
	}
	return a.probeNode(node, node.Port)
}

func (a *app) lockNodePassword(node managedNode) (string, error) {
	a.nodeOpMu.Lock()
	defer a.nodeOpMu.Unlock()
	if err := a.probeNode(node, node.Port); err != nil {
		return "", errors.New("密钥登录验证失败，拒绝关闭密码登录")
	}
	return a.runNodeScript(node, node.Port, nodeLockScript, 45*time.Second)
}

func (a *app) changeNodePort(node managedNode, newPort int) (string, error) {
	a.nodeOpMu.Lock()
	defer a.nodeOpMu.Unlock()
	if err := a.probeNode(node, node.Port); err != nil {
		return "", errors.New("旧端口密钥登录失败，拒绝修改端口")
	}
	out, err := a.runNodeScript(node, node.Port, nodePortPrepareScript, 45*time.Second, strconv.Itoa(node.Port), strconv.Itoa(newPort))
	if err != nil {
		rollback, rollbackErr := a.runNodeScript(node, node.Port, nodePortRollbackScript, 45*time.Second)
		if rollbackErr != nil {
			return out + "\n" + rollback, errors.New("新端口准备失败且自动回滚失败，请使用服务商控制台检查 SSH")
		}
		return out + "\n" + rollback, errors.New("新端口准备失败，已自动回滚旧配置")
	}
	if err := a.probeNode(node, newPort); err != nil {
		rollback, rollbackErr := a.runNodeScript(node, node.Port, nodePortRollbackScript, 45*time.Second)
		if rollbackErr != nil {
			return out + "\n" + rollback, errors.New("新端口不可达且自动回滚失败，请使用服务商控制台检查 SSH")
		}
		return out + "\n" + rollback, errors.New("新端口不可达，已自动回滚旧端口")
	}
	finalize, err := a.runNodeScript(node, newPort, nodePortFinalizeScript, 45*time.Second, strconv.Itoa(newPort))
	out += "\n" + finalize
	if err != nil {
		if probeErr := a.probeNode(node, newPort); probeErr == nil {
			node.Port = newPort
			if saveErr := a.upsertNode(node); saveErr != nil {
				return out, saveErr
			}
			return out, errors.New("新端口可用，但最终切换返回错误；旧端口可能仍开放")
		}
		return out, err
	}
	if err := a.probeNode(node, newPort); err != nil {
		return out, errors.New("新端口最终验证失败，请使用服务商控制台检查")
	}
	node.Port = newPort
	if err := a.upsertNode(node); err != nil {
		return out, err
	}
	return out, nil
}

func runCommandEnvInput(timeout time.Duration, input string, extraEnv []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output limitedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return output.String(), errors.New("命令执行超时")
	}
	return output.String(), err
}

func (a *app) startNodeJob(name string, r *http.Request, work func() (string, error)) *job {
	j := &job{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomToken(4)), Name: name, Status: "running", Started: time.Now()}
	a.mu.Lock()
	if a.jobs == nil {
		a.jobs = map[string]*job{}
	}
	a.jobs[j.ID] = j
	a.mu.Unlock()
	go func() {
		out, err := work()
		a.mu.Lock()
		j.Output, j.Finished = out, time.Now()
		if err != nil {
			j.Status, j.Error = "failed", err.Error()
		} else {
			j.Status = "success"
		}
		a.mu.Unlock()
		a.audit(r, "node.job", name, err == nil, "remote node operation completed")
	}()
	return j
}

const nodeLockScript = `set -eu
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else echo "需要 root 或 sudo" >&2; exit 1; fi
CFG=/etc/ssh/sshd_config
DIR=/etc/ssh/sshd_config.d
DROP="$DIR/00-kunpanel-hardening.conf"
STAMP=$(date +%Y%m%d%H%M%S)
BACKUP="$CFG.kunpanel.bak.$STAMP"
DROPBACKUP="$DROP.kunpanel.rollback"
$SUDO cp "$CFG" "$BACKUP"
$SUDO mkdir -p "$DIR"
if [ -f "$DROP" ]; then $SUDO cp "$DROP" "$DROPBACKUP"; else $SUDO rm -f "$DROPBACKUP"; fi
restore_config() { $SUDO cp "$BACKUP" "$CFG"; if [ -f "$DROPBACKUP" ]; then $SUDO cp "$DROPBACKUP" "$DROP"; else $SUDO rm -f "$DROP"; fi; }
reload_ssh() { if command -v systemctl >/dev/null 2>&1; then $SUDO systemctl reload sshd 2>/dev/null || $SUDO systemctl reload ssh; else $SUDO service sshd reload 2>/dev/null || $SUDO service ssh reload; fi; }
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d' "$CFG"; then TMP=$(mktemp); { echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat "$CFG"; } > "$TMP"; $SUDO install -m 644 "$TMP" "$CFG"; rm -f "$TMP"; fi
printf '%s\n' '# Managed by KunPanel' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'ChallengeResponseAuthentication no' 'PubkeyAuthentication yes' | $SUDO tee "$DROP" >/dev/null
if ! $SUDO sshd -t; then restore_config; exit 1; fi
EFF=$($SUDO sshd -T)
password=$(printf '%s\n' "$EFF" | awk 'tolower($1)=="passwordauthentication"{print $2;exit}')
keyboard=$(printf '%s\n' "$EFF" | awk 'tolower($1)=="kbdinteractiveauthentication"{print $2;exit}')
pubkey=$(printf '%s\n' "$EFF" | awk 'tolower($1)=="pubkeyauthentication"{print $2;exit}')
if [ "$password" != no ] || [ "$keyboard" != no ] || [ "$pubkey" != yes ]; then echo 'SSH 生效值不符合预期，已回滚' >&2; restore_config; exit 1; fi
if ! reload_ssh; then echo 'SSH 重载失败，已回滚' >&2; restore_config; reload_ssh || true; exit 1; fi
$SUDO rm -f "$DROPBACKUP"
echo 'OK: 密码和键盘交互登录已关闭，密钥登录保持启用'
`

const nodePortPrepareScript = `set -eu
OLD="$1"; NEW="$2"
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else exit 1; fi
CFG=/etc/ssh/sshd_config; DIR=/etc/ssh/sshd_config.d
DROP="$DIR/00-kunpanel-port.conf"; DROPBACKUP="$CFG.kunpanel-port.dropin.rollback"
$SUDO cp "$CFG" "$CFG.kunpanel-port.rollback"
$SUDO mkdir -p "$DIR"
if [ -f "$DROP" ]; then $SUDO cp "$DROP" "$DROPBACKUP"; else $SUDO rm -f "$DROPBACKUP"; fi
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d' "$CFG"; then TMP=$(mktemp); { echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat "$CFG"; } > "$TMP"; $SUDO install -m 644 "$TMP" "$CFG"; rm -f "$TMP"; fi
$SUDO sed -i -E 's/^([[:space:]]*Port[[:space:]]+.*)$/# KunPanel disabled: \1/I' "$CFG"
printf '# Managed by KunPanel\nPort %s\nPort %s\n' "$OLD" "$NEW" | $SUDO tee "$DROP" >/dev/null
if command -v ufw >/dev/null 2>&1; then $SUDO ufw allow "$NEW/tcp" >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then $SUDO firewall-cmd --permanent --add-port="$NEW/tcp" >/dev/null 2>&1 || true; $SUDO firewall-cmd --reload >/dev/null 2>&1 || true; fi
$SUDO sshd -t
if command -v systemctl >/dev/null 2>&1; then $SUDO systemctl restart sshd 2>/dev/null || $SUDO systemctl restart ssh; else $SUDO service sshd restart 2>/dev/null || $SUDO service ssh restart; fi
echo "OK: 新旧端口 $OLD/$NEW 已同时启用"
`

const nodePortRollbackScript = `set -eu
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else exit 1; fi
CFG=/etc/ssh/sshd_config; DIR=/etc/ssh/sshd_config.d
DROP="$DIR/00-kunpanel-port.conf"; DROPBACKUP="$CFG.kunpanel-port.dropin.rollback"
[ -f "$CFG.kunpanel-port.rollback" ] && $SUDO cp "$CFG.kunpanel-port.rollback" "$CFG"
if [ -f "$DROPBACKUP" ]; then $SUDO cp "$DROPBACKUP" "$DROP"; else $SUDO rm -f "$DROP"; fi
$SUDO sshd -t
if command -v systemctl >/dev/null 2>&1; then $SUDO systemctl restart sshd 2>/dev/null || $SUDO systemctl restart ssh; else $SUDO service sshd restart 2>/dev/null || $SUDO service ssh restart; fi
echo 'OK: 已恢复旧 SSH 端口配置'
`

const nodePortFinalizeScript = `set -eu
NEW="$1"
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else exit 1; fi
CFG=/etc/ssh/sshd_config; DIR=/etc/ssh/sshd_config.d; DROP="$DIR/00-kunpanel-port.conf"
printf '# Managed by KunPanel\nPort %s\n' "$NEW" | $SUDO tee "$DROP" >/dev/null
$SUDO sshd -t
if command -v systemctl >/dev/null 2>&1; then $SUDO systemctl restart sshd 2>/dev/null || $SUDO systemctl restart ssh; else $SUDO service sshd restart 2>/dev/null || $SUDO service ssh restart; fi
$SUDO rm -f "$CFG.kunpanel-port.rollback" "$CFG.kunpanel-port.dropin.rollback"
echo "OK: SSH 已切换到端口 $NEW"
`
