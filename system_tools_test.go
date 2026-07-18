package main

import "testing"

func TestParseProcessList(t *testing.T) {
	items := parseProcessList("123 root 12.5 3.4 90 nginx\ninvalid line\n")
	if len(items) != 1 || items[0].PID != 123 || items[0].Command != "nginx" || items[0].CPU != 12.5 {
		t.Fatalf("unexpected processes: %#v", items)
	}
}

func TestParseListeners(t *testing.T) {
	items := parseListeners("tcp LISTEN 0 4096 127.0.0.1:8088 0.0.0.0:* users:((\"panel\",pid=1,fd=3))\n")
	if len(items) != 1 || items[0].Protocol != "tcp" || items[0].Local != "127.0.0.1:8088" {
		t.Fatalf("unexpected listeners: %#v", items)
	}
}

func TestParseDisks(t *testing.T) {
	items := parseDisks("Filesystem 1-blocks Used Available Use% Mounted on\n/dev/vda1 1000 400 600 40% /\ntmpfs 100 1 99 1% /run\n")
	if len(items) != 1 || items[0].Filesystem != "/dev/vda1" || items[0].Used != 400 || items[0].Mount != "/" {
		t.Fatalf("unexpected disks: %#v", items)
	}
}

func TestKnownLogUnitUsesWhitelist(t *testing.T) {
	if !knownLogUnit("tryallfun-panel") || !knownLogUnit("nginx") || knownLogUnit("../../etc/passwd") {
		t.Fatal("log unit whitelist is incorrect")
	}
}
