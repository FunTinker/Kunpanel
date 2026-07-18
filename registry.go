package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type registryManifest struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Category    string              `json:"category"`
	Version     string              `json:"version"`
	Icon        string              `json:"icon"`
	Homepage    string              `json:"homepage"`
	License     string              `json:"license"`
	Tags        []string            `json:"tags"`
	Source      string              `json:"source"`
	InstallSize string              `json:"installSize"`
	Install     []string            `json:"install"`
	Update      []string            `json:"update"`
	Uninstall   []string            `json:"uninstall"`
	Checks      []string            `json:"checks"`
	Services    []string            `json:"services"`
	Config      []map[string]string `json:"config,omitempty"`
}

type registryFile struct {
	Version string             `json:"version"`
	Apps    []registryManifest `json:"apps"`
}

func (a *app) registryPath() string {
	return filepath.Join(a.dataDir, "apps", "registry.json")
}

func (a *app) allCatalog() []appSpec {
	items := append([]appSpec{}, catalog()...)
	custom, _ := a.loadRegistry()
	return append(items, custom...)
}

func (a *app) appCatalog() []map[string]any {
	out := appCatalog()
	for _, spec := range a.customSpecs() {
		installed := appInstalled(spec)
		out = append(out, map[string]any{
			"id": spec.ID, "name": spec.Name, "desc": spec.Desc, "category": spec.Category,
			"version": spec.Version, "icon": spec.Icon, "homepage": spec.Homepage, "license": spec.License,
			"tags": spec.Tags, "source": spec.Source, "installSize": spec.InstallSize,
			"verified": false, "installed": installed, "actions": appActions(spec, installed),
		})
	}
	return out
}

func (a *app) customSpecs() []appSpec {
	items, _ := a.loadRegistry()
	return items
}

func (a *app) loadRegistry() ([]appSpec, error) {
	b, err := os.ReadFile(a.registryPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var file registryFile
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, err
	}
	if len(file.Apps) > 100 {
		return nil, errors.New("registry contains too many applications")
	}
	items := make([]appSpec, 0, len(file.Apps))
	for _, manifest := range file.Apps {
		if err := validateManifest(manifest); err != nil {
			return nil, err
		}
		items = append(items, appSpec{ID: manifest.ID, Name: manifest.Name, Desc: manifest.Description, Category: manifest.Category, Version: manifest.Version, Icon: manifest.Icon, Homepage: manifest.Homepage, License: manifest.License, Tags: manifest.Tags, Source: manifest.Source, InstallSize: manifest.InstallSize, Commands: manifest.Install, Remove: manifest.Uninstall, Update: manifest.Update, Checks: manifest.Checks})
	}
	return items, nil
}

func validateManifest(manifest registryManifest) error {
	if !safeNameRE.MatchString(manifest.ID) || strings.TrimSpace(manifest.Name) == "" || strings.TrimSpace(manifest.Version) == "" {
		return errors.New("registry manifest has invalid id, name, or version")
	}
	if len(manifest.Install) == 0 || len(manifest.Install) > 20 {
		return errors.New("registry manifest must declare install commands")
	}
	for _, command := range append(append([]string{}, manifest.Install...), append(manifest.Update, manifest.Uninstall...)...) {
		if len(command) == 0 || len(command) > 4096 || strings.ContainsAny(command, "\x00\r\n") {
			return errors.New("registry command contains invalid characters")
		}
	}
	return nil
}

func (a *app) handleAppRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		b, err := os.ReadFile(a.registryPath())
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, 200, map[string]any{"path": a.registryPath(), "version": "1", "apps": []any{}})
			return
		}
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		var file registryFile
		if err := json.Unmarshal(b, &file); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"path": a.registryPath(), "version": file.Version, "apps": file.Apps})
		return
	}
	if r.Method != http.MethodPost || !a.requireRole(w, r, "admin") || !a.requireMaintenance(w, r) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	var file registryFile
	if !decodeJSON(w, r, &file) {
		return
	}
	if file.Version == "" {
		file.Version = "1"
	}
	seen := map[string]bool{}
	for _, manifest := range file.Apps {
		if seen[manifest.ID] {
			writeJSON(w, 400, map[string]string{"error": "应用 ID 重复"})
			return
		}
		seen[manifest.ID] = true
		if err := validateManifest(manifest); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
	}
	b, _ := json.MarshalIndent(file, "", "  ")
	if err := os.MkdirAll(filepath.Dir(a.registryPath()), 0700); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := atomicWrite(a.registryPath(), b, 0600); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.audit(r, "apps.registry", a.registryPath(), true, "local registry updated")
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(file.Apps)})
}
