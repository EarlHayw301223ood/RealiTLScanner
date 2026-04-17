package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	Fingerprint string
	HasReality  bool
	Latency     time.Duration
	Error       error
}

// Scanner performs TLS/Reality detection scans against targets.
type Scanner struct {
	Timeout    time.Duration
	Concurrent int
	Results    chan ScanResult
}

// NewScanner creates a Scanner with sensible defaults.
func NewScanner(timeout time.Duration, concurrent int) *Scanner {
	return &Scanner{
		Timeout:    timeout,
		Concurrent: concurrent,
		Results:    make(chan ScanResult, concurrent*2),
	}
}

// Scan initiates scanning over a list of address strings ("ip:port").
func (s *Scanner) Scan(targets []string) {
	sem := make(chan struct{}, s.Concurrent)
	for _, target := range targets {
		sem <- struct{}{}
		go func(addr string) {
			defer func() { <-sem }()
			s.Results <- s.scanOne(addr)
		}(target)
	}
	// Drain semaphore to wait for all goroutines.
	for i := 0; i < s.Concurrent; i++ {
		sem <- struct{}{}
	}
	close(s.Results)
}

// scanOne performs a TLS handshake against addr and detects Reality markers.
func (s *Scanner) scanOne(addr string) ScanResult {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ScanResult{IP: addr, Error: fmt.Errorf("invalid address: %w", err)}
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: s.Timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return ScanResult{IP: host, Port: port, Error: err}
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // We are probing; cert validity is not the goal.
		ServerName:         host,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(s.Timeout))

	if err := tlsConn.Handshake(); err != nil {
		return ScanResult{IP: host, Port: port, Latency: time.Since(start), Error: err}
	}
	latency := time.Since(start)

	state := tlsConn.ConnectionState()
	fingerprint := certFingerprint(state)
	hasReality := detectReality(state)

	serverName := state.ServerName
	if serverName == "" {
		serverName = host
	}

	return ScanResult{
		IP:          host,
		Port:        port,
		ServerName:  serverName,
		Fingerprint: fingerprint,
		HasReality:  hasReality,
		Latency:     latency,
	}
}

// certFingerprint returns a short identifier for the leaf certificate, if any.
func certFingerprint(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	cert := state.PeerCertificates[0]
	// Use Subject + serial as a lightweight fingerprint.
	return fmt.Sprintf("%s/%s", cert.Subject.CommonName, cert.SerialNumber.String())
}

// detectReality inspects the TLS state for known Reality/XTLS markers.
// Reality presents a valid TLS certificate while the underlying protocol
// differs; we use heuristics such as unusual ALPN or missing session tickets.
func detectReality(state tls.ConnectionState) bool {
	// Heuristic 1: No negotiated ALPN and no session ticket — common in Reality.
	if state.NegotiatedProtocol == "" && !state.DidResume {
		return true
	}
	// Heuristic 2: ALPN advertised as raw HTTP/1.1 without a matching cert SAN.
	if state.NegotiatedProtocol == "http/1.1" && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
			return true
		}
	}
	return false
}
