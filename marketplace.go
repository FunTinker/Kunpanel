package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed marketplace/catalog.json
var marketplaceData []byte

//go:embed deploy/install-docker.sh
var dockerInstallScript string

type marketplaceApp struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Desc         string            `json:"desc"`
	Category     string            `json:"category"`
	Repo         string            `json:"repo"`
	Image        string            `json:"image"`
	Port         int               `json:"port"`
	DefaultPort  int               `json:"defaultPort"`
	Volumes      []string          `json:"volumes"`
	Environment  map[string]string `json:"environment,omitempty"`
	Memory       string            `json:"memory"`
	License      string            `json:"license"`
	Note         string            `json:"note,omitempty"`
	Stars        int               `json:"stars,omitempty"`
	StarsChecked string            `json:"starsChecked,omitempty"`
}

type marketplaceInstall struct {
	ID        string    `json:"id"`
	Port      int       `json:"port"`
	URL       string    `json:"url"`
	Installed bool      `json:"installed"`
	Updated   time.Time `json:"updated"`
}

func marketplaceCatalog() []marketplaceApp {
	var items []marketplaceApp
	if err := json.Unmarshal(marketplaceData, &items); err != nil {
		panic(err)
	}
	return items
}

func marketplaceByID(id string) (marketplaceApp, bool) {
	for _, item := range marketplaceCatalog() {
		if item.ID == id {
			return item, true
		}
	}
	return marketplaceApp{}, false
}

func (a *app) marketplaceDir(id string) string { return filepath.Join(a.dataDir, "marketplace", id) }

func (a *app) marketplaceState(id string) marketplaceInstall {
	var state marketplaceInstall
	data, err := os.ReadFile(filepath.Join(a.marketplaceDir(id), "state.json"))
	if err == nil {
		_ = json.Unmarshal(data, &state)
	}
	return state
}

func (a *app) marketplaceInfo(item marketplaceApp, detail bool) map[string]any {
	state := a.marketplaceState(item.ID)
	actions := []string{"install"}
	if state.Installed {
		actions = []string{"start", "stop", "restart", "logs", "update", "uninstall"}
	}
	if state.Installed && fileExists(filepath.Join(a.marketplaceDir(item.ID), "rollback.json")) {
		actions = append(actions, "rollback")
	}
	info := map[string]any{
		"id": item.ID, "name": item.Name, "desc": item.Desc, "category": item.Category,
		"icon": strings.ToUpper(item.Name[:1]), "homepage": "https://github.com/" + item.Repo,
		"source": "GitHub / 官方容器镜像", "license": item.License, "version": strings.Split(item.Image, ":")[1],
		"verified": false, "containerized": true, "installed": state.Installed, "actions": actions,
		"tags": []string{"Docker Compose", item.Category}, "image": item.Image, "repo": item.Repo,
		"stars": item.Stars, "starsChecked": item.StarsChecked, "defaultPort": item.DefaultPort,
		"port": state.Port, "url": state.URL, "installSize": "内存上限 " + item.Memory,
		"note": item.Note, "services": []any{}, "config": []map[string]string{
			{"label": "镜像", "value": item.Image}, {"label": "内存上限", "value": item.Memory},
			{"label": "持久化卷", "value": strings.Join(item.Volumes, ", ")},
			{"label": "数据保留", "value": "卸载保留 Docker 数据卷；重装复用原数据"},
		},
	}
	if detail && state.Installed {
		out, err := runCommand(15*time.Second, "docker", "compose", "-f", filepath.Join(a.marketplaceDir(item.ID), "compose.json"), "ps", "-a", "--format", "json")
		if err == nil {
			info["runtime"] = out
		} else {
			info["runtimeError"] = outOrErr(out, err)
		}
	}
	if detail {
		info["compose"], _ = marketplaceCompose(item, item.DefaultPort, "", nil)
	}
	return info
}

func marketplaceCompose(item marketplaceApp, port int, externalURL string, secrets map[string]string) (string, error) {
	if port < 1024 || port > 65535 {
		return "", errors.New("端口必须在 1024 到 65535 之间")
	}
	if externalURL != "" {
		u, err := url.Parse(externalURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(externalURL, "\r\n\x00$") {
			return "", errors.New("应用地址必须是 HTTPS 根域名地址")
		}
	}
	environment := map[string]string{"TZ": "Asia/Shanghai"}
	for key, value := range item.Environment {
		environment[key] = value
	}
	for key, value := range secrets {
		environment[key] = value
	}
	if externalURL != "" {
		switch item.ID {
		case "vaultwarden":
			environment["DOMAIN"] = externalURL
		case "gitea":
			environment["GITEA__server__ROOT_URL"] = externalURL
		case "n8n":
			environment["N8N_EDITOR_BASE_URL"], environment["WEBHOOK_URL"] = externalURL, externalURL+"/"
		case "homepage":
			u, _ := url.Parse(externalURL)
			environment["HOMEPAGE_ALLOWED_HOSTS"] = u.Host
		}
	}
	volumes := map[string]any{}
	for _, volume := range item.Volumes {
		volumes[strings.SplitN(volume, ":", 2)[0]] = map[string]any{}
	}
	service := map[string]any{
		"image": item.Image, "restart": "unless-stopped", "ports": []string{fmt.Sprintf("127.0.0.1:%d:%d", port, item.Port)},
		"environment": environment, "volumes": item.Volumes, "mem_limit": item.Memory, "pids_limit": 256,
		"logging": map[string]any{"driver": "json-file", "options": map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	data, err := json.MarshalIndent(map[string]any{"name": "kun-" + item.ID, "services": map[string]any{"app": service}, "volumes": volumes}, "", "  ")
	return string(data), err
}

func (a *app) handleMarketplaceAction(w http.ResponseWriter, r *http.Request, item marketplaceApp, action string, port int, externalURL string) {
	if !oneOf(action, "install", "update", "uninstall", "start", "stop", "restart", "logs", "rollback") {
		writeJSON(w, 400, map[string]string{"error": "不支持的应用操作"})
		return
	}
	if !commandExists("docker") {
		writeJSON(w, 409, map[string]string{"error": "请先从应用市场安装 Docker"})
		return
	}
	dir := a.marketplaceDir(item.ID)
	composePath := filepath.Join(dir, "compose.json")
	state := a.marketplaceState(item.ID)
	if action == "logs" {
		if !state.Installed {
			writeJSON(w, 409, map[string]string{"error": "应用尚未安装"})
			return
		}
		out, err := runCommand(20*time.Second, "docker", "compose", "-f", composePath, "logs", "--tail", "200")
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
			return
		}
		writeJSON(w, 200, map[string]string{"output": out})
		return
	}
	if !a.marketplaceMu.TryLock() {
		writeJSON(w, 409, map[string]string{"error": "另一个应用操作正在进行，请等待完成"})
		return
	}
	// This lock spans the queued job as well, preventing two installs reserving the same port.
	if action == "install" && state.Installed || action != "install" && !state.Installed {
		a.marketplaceMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "应用安装状态已改变，请刷新"})
		return
	}
	if port == 0 {
		port = item.DefaultPort
	}
	secrets := map[string]string{}
	if item.ID == "linkding" && action == "install" && !fileExists(composePath) {
		secrets["LD_SUPERUSER_NAME"], secrets["LD_SUPERUSER_PASSWORD"] = "kunadmin", randomToken(24)
	}
	if item.ID == "vaultwarden" && action == "install" && !fileExists(composePath) {
		secrets["ADMIN_TOKEN"] = randomToken(32)
	}
	compose, err := marketplaceCompose(item, port, externalURL, secrets)
	if err != nil {
		a.marketplaceMu.Unlock()
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if action == "install" {
		if old, err := os.ReadFile(composePath); err == nil {
			compose = string(old)
			port, externalURL = state.Port, state.URL
		}
		listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			a.marketplaceMu.Unlock()
			writeJSON(w, 409, map[string]string{"error": "端口已被占用"})
			return
		}
		_ = listener.Close()
		if err := validateCompose(compose); err != nil {
			a.marketplaceMu.Unlock()
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			a.marketplaceMu.Unlock()
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := atomicWrite(composePath, []byte(compose), 0600); err != nil {
			a.marketplaceMu.Unlock()
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		state = marketplaceInstall{ID: item.ID, Port: port, URL: externalURL}
		data, _ := json.MarshalIndent(state, "", "  ")
		if err := atomicWrite(filepath.Join(dir, "state.json"), data, 0600); err != nil {
			a.marketplaceMu.Unlock()
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(a.marketplaceMu.Unlock) }
	job := a.startManagedJob("应用 "+action+" "+item.Name, r, func() (string, error) {
		defer release()
		var output strings.Builder
		run := func(args ...string) error {
			base := []string{"compose", "-f", composePath}
			out, err := runCommand(20*time.Minute, "docker", append(base, args...)...)
			output.WriteString(out + "\n")
			return err
		}
		var err error
		switch action {
		case "install":
			err = run("up", "-d", "--wait", "--wait-timeout", "180")
		case "update":
			var previous string
			previous, err = runCommand(30*time.Second, "docker", "compose", "-f", composePath, "config", "--resolve-image-digests")
			if err == nil {
				err = atomicWrite(filepath.Join(dir, "rollback.json"), []byte(previous), 0600)
			}
			if err == nil {
				err = run("pull")
			}
			if err == nil {
				err = run("up", "-d", "--wait", "--wait-timeout", "180")
			}
			if err != nil && previous != "" {
				out, rollbackErr := runCommand(4*time.Minute, "docker", "compose", "-f", filepath.Join(dir, "rollback.json"), "up", "-d", "--wait", "--wait-timeout", "180")
				output.WriteString("rollback: " + outOrErr(out, rollbackErr) + "\n")
			}
		case "uninstall":
			err = run("down")
		case "start":
			err = run("up", "-d", "--wait", "--wait-timeout", "180")
		case "stop":
			err = run("stop")
		case "restart":
			err = run("restart")
		case "rollback":
			var out string
			out, err = runCommand(4*time.Minute, "docker", "compose", "-f", filepath.Join(dir, "rollback.json"), "up", "-d", "--wait", "--wait-timeout", "180")
			output.WriteString(out + "\n")
		}
		if err == nil {
			state.Installed, state.Updated = action != "uninstall", time.Now()
			data, _ := json.MarshalIndent(state, "", "  ")
			err = atomicWrite(filepath.Join(dir, "state.json"), data, 0600)
		}
		return output.String(), err
	})
	a.mu.RLock()
	if job.Status != "running" {
		release()
	}
	result := map[string]any{"id": job.ID, "name": job.Name, "status": job.Status}
	a.mu.RUnlock()
	if len(secrets) > 0 {
		result["credentials"] = secrets
	}
	writeJSON(w, 202, result)
}
