package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidCron(t *testing.T) {
	if !validCron("0 3 * * *") {
		t.Fatal("valid cron rejected")
	}
	for _, value := range []string{"* * * *", "* * * * *; id", "@reboot"} {
		if validCron(value) {
			t.Fatalf("unsafe cron accepted: %s", value)
		}
	}
}

func TestBackupCommandUsesConfiguredDataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "custom-data")
	target := filepath.Join(dataDir, "backups", "panel.tar.gz")
	command := backupCommand(dataDir, target)
	if !strings.Contains(command, shellQuote(dataDir)) || !strings.Contains(command, "--exclude="+shellQuote(filepath.Join(dataDir, "backups"))) || strings.Contains(command, "/var/lib/tryallfun-panel") {
		t.Fatalf("backup command does not honor data directory: %s", command)
	}
}

func TestAutoOrangeThresholds(t *testing.T) {
	cfg := config{CloudflareCPUPercent: 80, CloudflareTrafficGB: 10}
	if autoOrangeThresholdReached(cfg, 79, 9) {
		t.Fatal("Cloudflare threshold triggered too early")
	}
	if !autoOrangeThresholdReached(cfg, 80, 1) || !autoOrangeThresholdReached(cfg, 1, 10) {
		t.Fatal("Cloudflare CPU or traffic threshold did not trigger")
	}
}

func TestSignedUpgradeManifest(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := upgradeManifest{
		Version: "1.2.3",
		URL:     "https://updates.example/panel",
		SHA256:  "0123456789abcdef",
	}
	message := manifest.Version + "\n" + manifest.URL + "\n" + manifest.SHA256
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer server.Close()
	got, err := fetchAndVerifyManifest(server.URL, base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != manifest.Version {
		t.Fatalf("version = %q", got.Version)
	}
}
