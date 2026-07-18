package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type processInfo struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Elapsed int64   `json:"elapsed"`
	Command string  `json:"command"`
}

type listenerInfo struct {
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Local    string `json:"local"`
	Peer     string `json:"peer"`
	Process  string `json:"process"`
}

type diskInfo struct {
	Filesystem string `json:"filesystem"`
	Size       uint64 `json:"size"`
	Used       uint64 `json:"used"`
	Available  uint64 `json:"available"`
	Percent    string `json:"percent"`
	Mount      string `json:"mount"`
}

func (a *app) handleSystemProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS == "windows" {
		writeJSON(w, 200, []processInfo{})
		return
	}
	out, err := runCommand(10*time.Second, "ps", "-eo", "pid,user,pcpu,pmem,etimes,comm", "--sort=-pcpu", "--no-headers")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, parseProcessList(out))
}

func parseProcessList(output string) []processInfo {
	items := make([]processInfo, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		memory, _ := strconv.ParseFloat(fields[3], 64)
		elapsed, _ := strconv.ParseInt(fields[4], 10, 64)
		items = append(items, processInfo{PID: pid, User: fields[1], CPU: cpu, Memory: memory, Elapsed: elapsed, Command: strings.Join(fields[5:], " ")})
		if len(items) >= 300 {
			break
		}
	}
	return items
}

func (a *app) handleSystemNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS == "windows" {
		writeJSON(w, 200, []listenerInfo{})
		return
	}
	out, err := runCommand(10*time.Second, "ss", "-lntupH")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, parseListeners(out))
}

func parseListeners(output string) []listenerInfo {
	items := make([]listenerInfo, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		process := ""
		if len(fields) > 6 {
			process = strings.Join(fields[6:], " ")
		}
		items = append(items, listenerInfo{Protocol: fields[0], State: fields[1], Local: fields[4], Peer: fields[5], Process: process})
	}
	return items
}

func (a *app) handleSystemDisks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS == "windows" {
		writeJSON(w, 200, []diskInfo{})
		return
	}
	out, err := runCommand(10*time.Second, "df", "-P", "-B1")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, parseDisks(out))
}

func parseDisks(output string) []diskInfo {
	items := make([]diskInfo, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || strings.HasPrefix(fields[0], "tmpfs") || strings.HasPrefix(fields[0], "udev") {
			continue
		}
		size, _ := strconv.ParseUint(fields[1], 10, 64)
		used, _ := strconv.ParseUint(fields[2], 10, 64)
		available, _ := strconv.ParseUint(fields[3], 10, 64)
		items = append(items, diskInfo{Filesystem: fields[0], Size: size, Used: used, Available: available, Percent: fields[4], Mount: strings.Join(fields[5:], " ")})
	}
	return items
}

func (a *app) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "tryallfun-panel"
	}
	if !knownLogUnit(unit) {
		writeJSON(w, 400, map[string]string{"error": "不支持的日志单元"})
		return
	}
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines < 1 || lines > 1000 {
		lines = 300
	}
	out, err := runCommand(15*time.Second, "journalctl", "-u", unit, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]any{"unit": unit, "lines": lines, "content": out})
}

func knownLogUnit(unit string) bool {
	if unit == "tryallfun-panel" {
		return true
	}
	return knownService(unit)
}

func (a *app) handleSystemAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Action string `json:"action"`
		PID    int    `json:"pid"`
		Signal string `json:"signal"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Action == "update-check" {
		writeJSON(w, 202, a.startJob("检查系统更新", []string{"apt-get update", "apt list --upgradable 2>/dev/null || true"}, r))
		return
	}
	if in.Action == "update-all" {
		writeJSON(w, 202, a.startJob("安装系统更新", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"}, r))
		return
	}
	if in.Action != "process-signal" || in.PID <= 1 || in.PID == os.Getpid() || !oneOf(in.Signal, "TERM", "KILL", "HUP") {
		writeJSON(w, 400, map[string]string{"error": "不支持的系统操作或参数"})
		return
	}
	out, err := runCommand(10*time.Second, "kill", "-"+in.Signal, strconv.Itoa(in.PID))
	a.audit(r, "process.signal", strconv.Itoa(in.PID), err == nil, outOrErr(out, err))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleDocker(w http.ResponseWriter, r *http.Request) {
	if !commandExists("docker") {
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{"installed": false, "containers": []any{}, "images": []any{}})
		} else {
			writeJSON(w, 409, map[string]string{"error": "Docker 尚未安装"})
		}
		return
	}
	if r.Method == http.MethodGet {
		containers, containerErr := dockerJSONLines("ps", "-a", "--format", "{{json .}}")
		images, imageErr := dockerJSONLines("images", "--format", "{{json .}}")
		if containerErr != nil || imageErr != nil {
			writeJSON(w, 500, map[string]string{"error": outOrErr("", firstError(containerErr, imageErr))})
			return
		}
		writeJSON(w, 200, map[string]any{"installed": true, "containers": containers, "images": images})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Action, ID string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !safeNameRE.MatchString(in.ID) || !oneOf(in.Action, "start", "stop", "restart", "remove") {
		writeJSON(w, 400, map[string]string{"error": "容器或操作无效"})
		return
	}
	args := []string{in.Action, in.ID}
	if in.Action == "remove" {
		args = []string{"rm", "-f", in.ID}
	}
	out, err := runCommand(2*time.Minute, "docker", args...)
	a.audit(r, "docker."+in.Action, in.ID, err == nil, outOrErr(out, err))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}

func dockerJSONLines(args ...string) ([]map[string]any, error) {
	out, err := runCommand(20*time.Second, "docker", args...)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		var item map[string]any
		if json.Unmarshal(scanner.Bytes(), &item) == nil {
			items = append(items, item)
		}
	}
	return items, scanner.Err()
}

func firstError(errors ...error) error {
	for _, err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}
