package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type cloudflareDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type cloudflareDNSResponse struct {
	Success bool                  `json:"success"`
	Result  []cloudflareDNSRecord `json:"result"`
	Errors  []map[string]any      `json:"errors"`
}

func (a *app) maybeAutoOrangeCloud(cpuPercent, trafficGB float64) {
	a.mu.Lock()
	cfg := a.cfg
	thresholdReached := autoOrangeThresholdReached(cfg, cpuPercent, trafficGB)
	if !cfg.CloudflareAutoOrangeCloud || !thresholdReached || cfg.CloudflareZoneID == "" || (cfg.CloudflareAPIToken == "" && cfg.CloudflareAPIKey == "") {
		a.cloudflareHighSince = time.Time{}
		a.mu.Unlock()
		return
	}
	now := time.Now()
	if a.cloudflareHighSince.IsZero() {
		a.cloudflareHighSince = now
		a.mu.Unlock()
		return
	}
	sustain := time.Duration(cfg.CloudflareSustainMinutes) * time.Minute
	if sustain < time.Minute {
		sustain = time.Minute
	}
	if now.Sub(a.cloudflareHighSince) < sustain || (!a.cloudflareLastAction.IsZero() && now.Sub(a.cloudflareLastAction) < time.Hour) {
		a.mu.Unlock()
		return
	}
	a.cloudflareLastAction = now
	a.mu.Unlock()

	go func() {
		count, err := enableCloudflareProxy(cfg)
		a.mu.Lock()
		if err != nil {
			a.cfg.CloudflareLastError = truncate(err.Error(), 500)
		} else {
			a.cfg.CloudflareLastSwitch = time.Now()
			a.cfg.CloudflareLastError = ""
		}
		saveErr := a.saveConfigUnlocked()
		a.mu.Unlock()
		if saveErr != nil && err == nil {
			err = saveErr
		}
		a.audit(nil, "cloudflare.auto-orange", cfg.CloudflareZoneID, err == nil, fmt.Sprintf("updated=%d %s", count, outOrErr("", err)))
	}()
}

func autoOrangeThresholdReached(cfg config, cpuPercent, trafficGB float64) bool {
	return (cfg.CloudflareCPUPercent > 0 && cpuPercent >= cfg.CloudflareCPUPercent) ||
		(cfg.CloudflareTrafficGB > 0 && trafficGB >= cfg.CloudflareTrafficGB)
}

func enableCloudflareProxy(cfg config) (int, error) {
	endpoint := "https://api.cloudflare.com/client/v4/zones/" + cfg.CloudflareZoneID + "/dns_records?per_page=100"
	var response cloudflareDNSResponse
	if err := cloudflareAPI(cfg, http.MethodGet, endpoint, nil, &response); err != nil {
		return 0, err
	}
	count := 0
	for _, record := range response.Result {
		if record.Proxied || !oneOf(record.Type, "A", "AAAA", "CNAME") {
			continue
		}
		body := map[string]any{"type": record.Type, "name": record.Name, "content": record.Content, "ttl": record.TTL, "proxied": true}
		if err := cloudflareAPI(cfg, http.MethodPatch, "https://api.cloudflare.com/client/v4/zones/"+cfg.CloudflareZoneID+"/dns_records/"+record.ID, body, nil); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func cloudflareAPI(cfg config, method, endpoint string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.CloudflareAPIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CloudflareAPIToken)
	} else {
		req.Header.Set("X-Auth-Email", cfg.CloudflareEmail)
		req.Header.Set("X-Auth-Key", cfg.CloudflareAPIKey)
	}
	client := http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare API 返回 %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(data)), 300))
	}
	var envelope struct {
		Success bool             `json:"success"`
		Errors  []map[string]any `json:"errors"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if !envelope.Success {
		return errors.New("Cloudflare API 操作失败")
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return err
		}
	}
	return nil
}
