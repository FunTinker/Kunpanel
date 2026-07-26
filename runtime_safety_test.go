package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSensitiveAuditFieldsAreRedacted(t *testing.T) {
	target, detail := safeAuditFields("terminal.execute", "curl -H 'Token: secret'", "password=secret")
	if strings.Contains(target, "secret") || strings.Contains(detail, "secret") {
		t.Fatalf("terminal audit retained sensitive content: %q %q", target, detail)
	}
	_, detail = safeAuditFields("pty.command", "session", "sudo-password")
	if strings.Contains(detail, "sudo-password") {
		t.Fatal("PTY input retained in audit detail")
	}
}

func TestLegacyAuditMigrationRemovesSensitiveContent(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "audit.jsonl")
	entry, _ := json.Marshal(auditEntry{Action: "terminal.execute", Target: "token=secret", Detail: "password=secret"})
	if err := os.WriteFile(path, append(entry, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacyAuditLogs(dataDir); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), "secret") {
		t.Fatalf("legacy audit secret remained: %s", content)
	}
}

func TestAuditRotationAndBoundedRead(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	path := filepath.Join(a.dataDir, "audit.jsonl")
	for i := 0; i < 205; i++ {
		entry, _ := json.Marshal(auditEntry{Time: time.Unix(int64(i), 0), Action: "test"})
		a.appendAuditLine(path, append(entry, '\n'))
	}
	entries := readRecentAuditEntries(path, 200)
	if len(entries) != 200 || !entries[0].Time.Equal(time.Unix(204, 0)) {
		t.Fatalf("unexpected recent audit entries: len=%d first=%v", len(entries), entries[0].Time)
	}
	if err := os.WriteFile(path, make([]byte, maxAuditBytes), 0600); err != nil {
		t.Fatal(err)
	}
	a.appendAuditLine(path, []byte("{}\n"))
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("audit archive was not created: %v", err)
	}
}

func TestJobRetentionAndOutputLimit(t *testing.T) {
	a := &app{jobs: map[string]*job{}}
	for i := 0; i < maxRetainedJobs+10; i++ {
		j := &job{ID: randomToken(8), Status: "success", Started: time.Unix(int64(i), 0)}
		a.registerJobLocked(j)
	}
	if len(a.jobs) != maxRetainedJobs {
		t.Fatalf("retained jobs = %d", len(a.jobs))
	}
	if got := trimJobOutput(strings.Repeat("x", maxJobOutput+100)); len(got) > maxJobOutput {
		t.Fatalf("trimmed output remains too large: %d", len(got))
	}
}

func TestJobRetentionRejectsWhenEveryJobIsRunning(t *testing.T) {
	a := &app{jobs: map[string]*job{}}
	for i := 0; i < maxRetainedJobs; i++ {
		a.jobs[randomToken(8)] = &job{Status: "running", Started: time.Now()}
	}
	newJob := &job{ID: "overflow", Status: "running", Started: time.Now()}
	if a.registerJobLocked(newJob) || newJob.Status != "failed" || len(a.jobs) != maxRetainedJobs {
		t.Fatalf("running job hard limit was not enforced: registered=%v status=%s len=%d", a.jobs[newJob.ID] != nil, newJob.Status, len(a.jobs))
	}
}

func TestRestoreManagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.conf")
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreManagedFile(path, []byte("old"), 0640, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatalf("restored content = %q", got)
	}
}

func TestClientIPTrustsHeadersOnlyFromLoopbackProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://panel.local", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Header.Set("X-Real-IP", "198.51.100.2")
	if got := clientIP(req); got != "203.0.113.5" {
		t.Fatalf("untrusted forwarding header accepted: %s", got)
	}
	req.RemoteAddr = "127.0.0.1:1234"
	if got := clientIP(req); got != "198.51.100.2" {
		t.Fatalf("trusted proxy header ignored: %s", got)
	}
}
