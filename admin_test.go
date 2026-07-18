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
