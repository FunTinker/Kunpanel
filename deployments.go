package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type deploymentProject struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Repo      string    `json:"repo,omitempty"`
	Branch    string    `json:"branch,omitempty"`
	Compose   string    `json:"compose,omitempty"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	LastError string    `json:"lastError,omitempty"`
}

func (a *app) deploymentsDir() string {
	return filepath.Join(a.dataDir, "deployments")
}

func (a *app) handleDeployments(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		items, err := a.loadDeployments()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if id := r.URL.Query().Get("id"); id != "" {
			for _, item := range items {
				if item.ID == id {
					writeJSON(w, 200, item)
					return
				}
			}
			writeJSON(w, 404, map[string]string{"error": "部署项目不存在"})
			return
		}
		writeJSON(w, 200, items)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Action  string `json:"action"`
		ID      string `json:"id"`
		Name    string `json:"name"`
		Compose string `json:"compose"`
		Repo    string `json:"repo"`
		Branch  string `json:"branch"`
		Confirm string `json:"confirm"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !oneOf(in.Action, "create", "update", "delete", "up", "down", "restart", "logs", "git-clone", "git-pull") {
		writeJSON(w, 400, map[string]string{"error": "不支持的部署操作"})
		return
	}
	if in.Action == "git-clone" {
		if !validGitURL(in.Repo) || !safeNameRE.MatchString(in.ID) {
			writeJSON(w, 400, map[string]string{"error": "Git 仓库或项目 ID 无效"})
			return
		}
		branch := in.Branch
		if branch == "" {
			branch = "main"
		}
		if !safeNameRE.MatchString(branch) {
			writeJSON(w, 400, map[string]string{"error": "Git 分支名无效"})
			return
		}
		dir := filepath.Join(a.deploymentsDir(), in.ID, "source")
		if _, err := safePath(a.deploymentsDir(), dir); err != nil {
			writeJSON(w, 400, map[string]string{"error": "部署目录无效"})
			return
		}
		item := deploymentProject{ID: in.ID, Name: cleanNote(in.Name), Repo: in.Repo, Branch: branch, Path: dir, Created: time.Now(), Updated: time.Now()}
		if item.Name == "" {
			item.Name = item.ID
		}
		if err := a.writeDeploymentMeta(item); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		commands := [][]string{{"git", "clone", "--depth", "1", "--branch", branch, in.Repo, dir}}
		j := a.startArgsJob("拉取 Git 项目 "+in.ID, commands, r)
		writeJSON(w, 202, j)
		return
	}
	if !safeNameRE.MatchString(in.ID) {
		writeJSON(w, 400, map[string]string{"error": "项目 ID 无效"})
		return
	}
	items, err := a.loadDeployments()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	index := -1
	for i := range items {
		if items[i].ID == in.ID {
			index = i
			break
		}
	}
	if in.Action == "create" {
		if index >= 0 {
			writeJSON(w, 409, map[string]string{"error": "项目已存在"})
			return
		}
		if len(in.Compose) == 0 || len(in.Compose) > 512*1024 {
			writeJSON(w, 400, map[string]string{"error": "Compose 文件为空或超过 512 KB"})
			return
		}
		item := deploymentProject{ID: in.ID, Name: cleanNote(in.Name), Repo: in.Repo, Branch: in.Branch, Compose: in.Compose, Created: time.Now(), Updated: time.Now()}
		if item.Name == "" {
			item.Name = item.ID
		}
		if err := a.writeDeployment(item); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "deployment.create", in.ID, true, item.Name)
		writeJSON(w, 201, item)
		return
	}
	if index < 0 {
		writeJSON(w, 404, map[string]string{"error": "部署项目不存在"})
		return
	}
	item := items[index]
	dir := filepath.Join(a.deploymentsDir(), item.ID)
	if item.Path == "" {
		item.Path = dir
	}
	composePath := filepath.Join(dir, "docker-compose.yml")
	if in.Action == "update" {
		if len(in.Compose) == 0 || len(in.Compose) > 512*1024 {
			writeJSON(w, 400, map[string]string{"error": "Compose 文件为空或超过 512 KB"})
			return
		}
		item.Compose, item.Updated = in.Compose, time.Now()
		if err := a.writeDeployment(item); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, item)
		return
	}
	if in.Action == "delete" {
		if in.Confirm != "DELETE "+item.ID {
			writeJSON(w, 400, map[string]string{"error": "删除确认文本不正确"})
			return
		}
		if err := os.RemoveAll(dir); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditTarget := item.ID
		a.audit(r, "deployment.delete", auditTarget, true, "project removed")
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if in.Action == "git-pull" {
		projectPath := filepath.Join(dir, "source")
		if _, err := os.Stat(filepath.Join(projectPath, ".git")); err != nil {
			writeJSON(w, 400, map[string]string{"error": "项目不是 Git 工作树"})
			return
		}
		writeJSON(w, 202, a.startArgsJob("更新 Git 项目 "+item.ID, [][]string{{"git", "-C", projectPath, "pull", "--ff-only"}}, r))
		return
	}
	if _, err := os.Stat(composePath); err != nil {
		writeJSON(w, 400, map[string]string{"error": "Compose 文件不存在"})
		return
	}
	if in.Action == "logs" {
		out, err := runCommand(2*time.Minute, "docker", "compose", "-f", composePath, "logs", "--tail", "200")
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
			return
		}
		writeJSON(w, 200, map[string]string{"output": out})
		return
	}
	composeAction := map[string]string{"up": "up", "down": "down", "restart": "restart"}[in.Action]
	args := []string{"compose", "-f", composePath, composeAction}
	if in.Action == "up" {
		args = append(args, "-d")
	}
	command := append([]string{"docker"}, args...)
	writeJSON(w, 202, a.startArgsJob("Compose "+in.Action+" "+item.ID, [][]string{command}, r))
}

func (a *app) loadDeployments() ([]deploymentProject, error) {
	if err := os.MkdirAll(a.deploymentsDir(), 0700); err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(a.deploymentsDir(), "*.json"))
	if err != nil {
		return nil, err
	}
	items := make([]deploymentProject, 0, len(files))
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var item deploymentProject
		if json.Unmarshal(b, &item) == nil && safeNameRE.MatchString(item.ID) {
			items = append(items, item)
		}
	}
	return items, nil
}

func (a *app) writeDeployment(item deploymentProject) error {
	if !safeNameRE.MatchString(item.ID) {
		return errors.New("invalid deployment id")
	}
	dir := filepath.Join(a.deploymentsDir(), item.ID)
	if item.Path == "" {
		item.Path = dir
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(item.Compose), 0600); err != nil {
		return err
	}
	return a.writeDeploymentMeta(item)
}

func (a *app) writeDeploymentMeta(item deploymentProject) error {
	b, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.deploymentsDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.deploymentsDir(), item.ID+".json"), b, 0600)
}

func validGitURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return strings.HasPrefix(raw, "git@") && !strings.ContainsAny(raw, "\r\n;|&`$()")
	}
	return oneOf(u.Scheme, "https", "ssh", "git") && u.Host != "" && !strings.ContainsAny(raw, "\r\n;|&`$()")
}

func (a *app) startArgsJob(name string, commands [][]string, r *http.Request) *job {
	j := &job{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomToken(4)), Name: name, Status: "running", Started: time.Now()}
	a.mu.Lock()
	a.jobs[j.ID] = j
	a.mu.Unlock()
	go func() {
		var output strings.Builder
		var finalErr error
		for _, args := range commands {
			if len(args) == 0 {
				continue
			}
			output.WriteString("$ " + strings.Join(args, " ") + "\n")
			out, err := runCommand(20*time.Minute, args[0], args[1:]...)
			output.WriteString(out + "\n")
			if err != nil {
				finalErr = err
				break
			}
		}
		a.mu.Lock()
		j.Output, j.Finished = output.String(), time.Now()
		if finalErr != nil {
			j.Status, j.Error = "failed", finalErr.Error()
		} else {
			j.Status = "success"
		}
		a.mu.Unlock()
		a.audit(r, "job.args", name, finalErr == nil, outOrErr(j.Output, finalErr))
	}()
	return j
}
