package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
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
	vhost := filepath.Join(t.TempDir(), "nginx-conf")
	ssl := filepath.Join(t.TempDir(), "nginx-ssl")
	t.Setenv("TAF_NGINX_VHOST_DIR", vhost)
	t.Setenv("TAF_NGINX_SSL_DIR", ssl)
	command := backupCommand(dataDir, target)
	if !strings.Contains(command, shellQuote(dataDir)) || !strings.Contains(command, shellQuote(vhost)) || !strings.Contains(command, shellQuote(ssl)) || !strings.Contains(command, "--exclude="+shellQuote(filepath.Join(dataDir, "backups"))) || !strings.Contains(command, "--exclude="+shellQuote(strings.TrimPrefix(filepath.ToSlash(filepath.Join(dataDir, "backups")), "/"))) || strings.Contains(command, "/var/lib/tryallfun-panel") {
		t.Fatalf("backup command does not honor data directory: %s", command)
	}
}

func TestValidateBackupArchiveRejectsUnexpectedPathAndLinks(t *testing.T) {
	writeArchive := func(name string, typeFlag byte) string {
		path := filepath.Join(t.TempDir(), "backup.tar.gz")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: typeFlag, Mode: 0600, Size: 0}); err != nil {
			t.Fatal(err)
		}
		_ = tw.Close()
		_ = gz.Close()
		_ = f.Close()
		return path
	}
	allowed := []string{"/var/lib/tryallfun-panel"}
	if err := validateBackupArchive(writeArchive("var/lib/tryallfun-panel/config.json", tar.TypeReg), allowed); err != nil {
		t.Fatalf("valid backup rejected: %v", err)
	}
	if err := validateBackupArchive(writeArchive("etc/shadow", tar.TypeReg), allowed); err == nil {
		t.Fatal("unexpected backup path accepted")
	}
	if err := validateBackupArchive(writeArchive("var/lib/tryallfun-panel/link", tar.TypeSymlink), allowed); err == nil {
		t.Fatal("backup symlink accepted")
	}
}

func TestUpgradeScriptIncludesHealthRollback(t *testing.T) {
	script := upgradeRollbackScript("/opt/kunpanel/kunpanel", "/opt/kunpanel/kunpanel.update", "/opt/kunpanel/kunpanel.rollback", "kunpanel", "http://127.0.0.1:8088")
	for _, want := range []string{"systemctl restart 'kunpanel'", "api/status", "kunpanel.rollback", "curl -fsS"} {
		if !strings.Contains(script, want) {
			t.Fatalf("upgrade rollback script missing %q: %s", want, script)
		}
	}
}

func TestUpgradeHealthURLMustBeLoopback(t *testing.T) {
	t.Setenv("TAF_SERVICE_NAME", "kunpanel")
	t.Setenv("TAF_HEALTH_URL", "http://127.0.0.1:8088@evil.example")
	if _, _, err := upgradeRuntimeSettings(); err == nil {
		t.Fatal("non-loopback upgrade health URL accepted")
	}
	t.Setenv("TAF_HEALTH_URL", "http://127.0.0.1:8088")
	if _, _, err := upgradeRuntimeSettings(); err != nil {
		t.Fatalf("loopback upgrade health URL rejected: %v", err)
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
	if err := verifyUpgradeManifest(manifest, base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
}
