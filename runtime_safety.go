package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxAuditBytes    = 10 << 20
	maxAuditArchives = 5
	maxRetainedJobs  = 100
	maxJobOutput     = 512 << 10
)

var jobExecutionSlots = make(chan struct{}, 4)

func safeAuditFields(action, target, detail string) (string, string) {
	switch action {
	case "pty.command":
		detail = "interactive input submitted"
	case "terminal.execute":
		target, detail = "interactive shell", "command completed"
	case "database.query":
		detail = "SQL query completed"
	case "job.run", "job.args":
		detail = "background job completed"
	}
	clean := func(value string, limit int) string {
		value = strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return ' '
			}
			return r
		}, value)
		return truncate(strings.TrimSpace(value), limit)
	}
	return clean(target, 512), clean(detail, 4000)
}

func migrateLegacyAuditLogs(dataDir string) error {
	marker := filepath.Join(dataDir, ".audit-v2-migrated")
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	base := filepath.Join(dataDir, "audit.jsonl")
	for archive := maxAuditArchives; archive >= 0; archive-- {
		path := base
		if archive > 0 {
			path += "." + strconv.Itoa(archive)
		}
		if err := sanitizeAuditFile(path); err != nil {
			return err
		}
	}
	return atomicWrite(marker, []byte("v2\n"), 0600)
}

func sanitizeAuditFile(path string) error {
	in, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".sanitize." + randomToken(4)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	for scanner.Scan() {
		var entry auditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		entry.Target, entry.Detail = safeAuditFields(entry.Action, entry.Target, entry.Detail)
		line, _ := json.Marshal(entry)
		if _, err := out.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := in.Close(); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func (a *app) appendAuditLine(path string, line []byte) {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line)) > maxAuditBytes {
		rotateAuditLogs(path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	_, _ = f.Write(line)
	_ = f.Close()
}

func rotateAuditLogs(path string) {
	for i := maxAuditArchives; i >= 1; i-- {
		oldPath := path
		if i > 1 {
			oldPath = path + "." + strconv.Itoa(i-1)
		}
		newPath := path + "." + strconv.Itoa(i)
		_ = os.Remove(newPath)
		if _, err := os.Stat(oldPath); err == nil {
			_ = os.Rename(oldPath, newPath)
		}
	}
}

func readRecentAuditEntries(path string, limit int) []auditEntry {
	if limit <= 0 {
		return []auditEntry{}
	}
	result := make([]auditEntry, 0, limit)
	for archive := 0; archive <= maxAuditArchives && len(result) < limit; archive++ {
		candidate := path
		if archive > 0 {
			candidate += "." + strconv.Itoa(archive)
		}
		entries := scanAuditFile(candidate, limit-len(result))
		for i := len(entries) - 1; i >= 0; i-- {
			result = append(result, entries[i])
		}
	}
	return result
}

func scanAuditFile(path string, limit int) []auditEntry {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil
	}
	defer f.Close()
	ring := make([]auditEntry, limit)
	count, next := 0, 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	for scanner.Scan() {
		var entry auditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		ring[next] = entry
		next = (next + 1) % limit
		if count < limit {
			count++
		}
	}
	entries := make([]auditEntry, 0, count)
	start := 0
	if count == limit {
		start = next
	}
	for i := 0; i < count; i++ {
		entries = append(entries, ring[(start+i)%limit])
	}
	return entries
}

func (a *app) registerJobLocked(j *job) bool {
	if a.jobs == nil {
		a.jobs = map[string]*job{}
	}
	if len(a.jobs) >= maxRetainedJobs {
		var oldest *job
		for _, item := range a.jobs {
			if item.Status != "running" && (oldest == nil || item.Started.Before(oldest.Started)) {
				oldest = item
			}
		}
		if oldest != nil {
			delete(a.jobs, oldest.ID)
		}
	}
	if len(a.jobs) >= maxRetainedJobs {
		j.Status = "failed"
		j.Error = "后台任务过多，请等待现有任务完成"
		j.Finished = time.Now()
		return false
	}
	a.jobs[j.ID] = j
	return true
}

func (a *app) pruneJobsLocked() {
	if len(a.jobs) <= maxRetainedJobs {
		return
	}
	finished := make([]*job, 0, len(a.jobs))
	for _, item := range a.jobs {
		if item.Status != "running" {
			finished = append(finished, item)
		}
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].Started.Before(finished[j].Started) })
	remove := len(a.jobs) - maxRetainedJobs
	if remove > len(finished) {
		remove = len(finished)
	}
	for _, item := range finished[:remove] {
		delete(a.jobs, item.ID)
	}
}

func trimJobOutput(value string) string {
	if len(value) <= maxJobOutput {
		return value
	}
	const prefix = "[earlier output truncated]\n"
	start := len(value) - maxJobOutput + len(prefix)
	for start < len(value) && value[start]&0xc0 == 0x80 {
		start++
	}
	return prefix + value[start:]
}

func acquireJobExecutionSlot() func() {
	jobExecutionSlots <- struct{}{}
	return func() { <-jobExecutionSlots }
}
