package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxUpgradeBytes = 128 << 20

func validatePublicHTTPSURL(raw string) (*url.URL, error) {
	if strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("URL contains invalid control characters")
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, errors.New("URL must be an absolute HTTPS address")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("URL credentials and fragments are not allowed")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("URL port is invalid")
		}
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if strings.Contains(hostname, "%") || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return nil, errors.New("URL points to a local address")
	}
	if ip := net.ParseIP(hostname); ip != nil && !privateOutboundAllowed() {
		if err := validateOutboundIP(ip); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}

func newPublicHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A proxy can hide the request destination from DialContext, so user-configured
	// outbound URLs deliberately use direct connections.
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if privateOutboundAllowed() {
			return dialer.DialContext(ctx, network, address)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, errors.New("outbound host did not resolve")
		}
		for _, address := range addresses {
			if err := validateOutboundIP(address.IP); err != nil {
				return nil, err
			}
		}
		var lastErr error
		for _, address := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			_, err := validatePublicHTTPSURL(req.URL.String())
			return err
		},
	}
}

func validateOutboundIP(ip net.IP) error {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return errors.New("outbound URL resolves to a private or local address")
	}
	for _, cidr := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "2001:db8::/32"} {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return errors.New("outbound URL resolves to a reserved address")
		}
	}
	return nil
}

func privateOutboundAllowed() bool {
	return os.Getenv("TAF_ALLOW_PRIVATE_OUTBOUND") == "1"
}

func doPublicRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("outbound request URL is missing")
	}
	if _, err := validatePublicHTTPSURL(req.URL.String()); err != nil {
		return nil, err
	}
	return client.Do(req)
}

func downloadPublicHTTPSFile(rawURL, destination string, maxBytes int64) error {
	parsed, err := validatePublicHTTPSURL(rawURL)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	response, err := doPublicRequest(newPublicHTTPClient(5*time.Minute), request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("upgrade source returned %d", response.StatusCode)
	}
	if response.ContentLength > maxBytes {
		return errors.New("upgrade package exceeds the size limit")
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".kunpanel-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	written, err := io.Copy(tmp, io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return errors.New("upgrade package exceeds the size limit")
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(0755); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	ok = true
	return nil
}
