package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildProxySiteConfig(t *testing.T) {
	t.Setenv("TAF_NGINX_SSL_DIR", t.TempDir())
	conf, err := buildSiteConfig("api.example.com", "proxy", "", "http://127.0.0.1:3000", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"managed-by: tryallfun-panel", "server_name api.example.com", "proxy_pass http://127.0.0.1:3000"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("config missing %q", want)
		}
	}
}

func TestFindWildcardCertificate(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "www.example.com")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.cer"), []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "www.example.com.key"), []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAF_NGINX_SSL_DIR", root)
	cert, key := findCertificate("panel.example.com")
	if cert == "" || key == "" {
		t.Fatal("wildcard certificate directory was not found")
	}
}

func TestValidUpstreamRejectsNginxInjection(t *testing.T) {
	if validUpstream("http://127.0.0.1:3000;\nserver{}") {
		t.Fatal("unsafe upstream accepted")
	}
}

func TestSafePathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := safePath(root, filepath.Join(root, "..", "outside")); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestCatalogIncludesCoreMarketplaceApps(t *testing.T) {
	items := catalog()
	want := map[string]bool{"docker": false, "nodejs": false, "postgres": false, "laravel": false, "certbot": false}
	for _, item := range items {
		if _, ok := want[item.ID]; ok {
			want[item.ID] = true
		}
		if item.ID != "wordpress" && (item.Version == "" || item.Homepage == "" || len(item.Tags) == 0 || len(item.Commands) == 0 || len(item.Remove) == 0) {
			t.Fatalf("app %q is missing marketplace metadata or lifecycle commands", item.ID)
		}
	}
	for id, found := range want {
		if !found {
			t.Fatalf("marketplace app %q is missing", id)
		}
	}
}

func TestAppActionsRespectInstallState(t *testing.T) {
	spec := packageApp("demo", "Demo", "Demo", "测试", "1", "D", "https://example.com", "MIT", []string{"demo"}, []string{"demo"}, []string{"demo"})
	if got := appActions(spec, false); len(got) != 1 || got[0] != "install" {
		t.Fatalf("uninstalled actions = %#v", got)
	}
	if got := appActions(spec, true); len(got) != 2 || got[0] != "update" || got[1] != "uninstall" {
		t.Fatalf("installed actions = %#v", got)
	}
}
