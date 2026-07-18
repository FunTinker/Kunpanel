package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestValidateNode(t *testing.T) {
	valid := managedNode{Alias: "tokyo-1", Host: "203.0.113.10", User: "root", Port: 22}
	if err := validateNode(valid); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"host;id", "bad host", "$(id)", ""} {
		valid.Host = host
		if validateNode(valid) == nil {
			t.Fatalf("unsafe node host accepted: %q", host)
		}
	}
}

func TestNodePersistenceAndFuzzyResolution(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	for _, node := range []managedNode{{Alias: "tokyo-1", Host: "203.0.113.10", User: "root", Port: 22}, {Alias: "hongkong-1", Host: "example.com", User: "deploy", Port: 2222}} {
		if err := a.upsertNode(node); err != nil {
			t.Fatal(err)
		}
	}
	got, err := a.resolveNode("tok")
	if err != nil || got.Alias != "tokyo-1" {
		t.Fatalf("fuzzy resolve = %#v, %v", got, err)
	}
	if got.Created.IsZero() || got.Updated.IsZero() {
		t.Fatalf("persisted node is missing timestamps: %#v", got)
	}
	b, err := os.ReadFile(a.nodesPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "password") {
		t.Fatalf("node storage contains password field: %s", b)
	}
	if _, err := a.resolveNode(""); err == nil {
		t.Fatal("empty alias unexpectedly resolved a node")
	}
}

func TestConcurrentNodeUpsertsDoNotLoseNodes(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			node := managedNode{Alias: fmt.Sprintf("node-%02d", index), Host: fmt.Sprintf("node-%02d.example.com", index), User: "root", Port: 22}
			if err := a.upsertNode(node); err != nil {
				t.Errorf("upsert %d: %v", index, err)
			}
		}(i)
	}
	wg.Wait()
	items, err := a.loadNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 50 {
		t.Fatalf("saved %d nodes, want 50", len(items))
	}
}

func TestNodeHardeningScriptsValidateAndRollback(t *testing.T) {
	for name, script := range map[string]string{"lock": nodeLockScript, "prepare": nodePortPrepareScript, "rollback": nodePortRollbackScript, "finalize": nodePortFinalizeScript} {
		if !strings.Contains(script, "sshd -t") {
			t.Fatalf("%s script does not validate sshd configuration", name)
		}
	}
	if !strings.Contains(nodePortPrepareScript, "Port %s\\nPort %s") || !strings.Contains(nodePortRollbackScript, "kunpanel-port.rollback") {
		t.Fatal("port migration is missing dual-port transition or rollback")
	}
	if !strings.Contains(nodePortPrepareScript, "kunpanel-port.dropin.rollback") || !strings.Contains(nodePortRollbackScript, "cp \"$DROPBACKUP\" \"$DROP\"") {
		t.Fatal("port migration does not preserve the previous KunPanel port drop-in")
	}
	if !strings.Contains(nodeLockScript, `DROPBACKUP="$DROP.kunpanel.rollback"`) || !strings.Contains(nodeLockScript, "restore_config") {
		t.Fatal("password hardening does not preserve and restore its previous drop-in")
	}
}
