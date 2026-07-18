package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func (a *app) metricHistoryPath() string {
	return filepath.Join(a.dataDir, "metrics-minute.jsonl")
}

func (a *app) loadMetricHistory() error {
	f, err := os.Open(a.metricHistoryPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	cutoff := time.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var point sample
		if json.Unmarshal(scanner.Bytes(), &point) == nil && point.Time >= cutoff {
			a.history = append(a.history, point)
			a.lastPersistMinute = point.Time / 60000
		}
	}
	return scanner.Err()
}

func (a *app) appendMetricHistory(point sample) {
	b, err := json.Marshal(point)
	if err != nil {
		return
	}
	f, err := os.OpenFile(a.metricHistoryPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	// 每天重写一次文件，移除超过 30 天的分钟数据。
	if point.Time/60000%1440 == 0 {
		a.mu.RLock()
		history := append([]sample(nil), a.history...)
		a.mu.RUnlock()
		tmp := a.metricHistoryPath() + ".compact"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		enc := json.NewEncoder(out)
		for _, item := range history {
			if enc.Encode(item) != nil {
				_ = out.Close()
				_ = os.Remove(tmp)
				return
			}
		}
		_ = out.Close()
		_ = os.Rename(tmp, a.metricHistoryPath())
	}
}
