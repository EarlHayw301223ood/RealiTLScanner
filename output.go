package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the result of scanning a single IP/host.
type ScanResult struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	IsReality   bool      `json:"is_reality"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	ServerName  string    `json:"server_name,omitempty"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	Latency     int64     `json:"latency_ms"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// OutputWriter handles writing scan results to various formats.
type OutputWriter struct {
	mu      sync.Mutex
	format  string
	file    *os.File
	csvW    *csv.Writer
	results []ScanResult
}

// NewOutputWriter creates a new OutputWriter for the given format and output path.
// format can be "json", "csv", or "text".
// If path is empty, stdout is used.
func NewOutputWriter(format, path string) (*OutputWriter, error) {
	var f *os.File
	var err error

	if path == "" {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file: %w", err)
		}
	}

	ow := &OutputWriter{
		format:  format,
		file:    f,
		results: make([]ScanResult, 0),
	}

	if format == "csv" {
		ow.csvW = csv.NewWriter(f)
		// Write CSV header
		_ = ow.csvW.Write([]string{
			"ip", "port", "is_reality", "fingerprint",
			"server_name", "country", "asn", "latency_ms", "scanned_at", "error",
		})
	}

	return ow, nil
}

// Write appends a ScanResult to the output.
func (ow *OutputWriter) Write(r ScanResult) error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	switch ow.format {
	case "json":
		ow.results = append(ow.results, r)
	case "csv":
		err := ow.csvW.Write([]string{
			r.IP,
			fmt.Sprintf("%d", r.Port),
			fmt.Sprintf("%t", r.IsReality),
			r.Fingerprint,
			r.ServerName,
			r.Country,
			r.ASN,
			fmt.Sprintf("%d", r.Latency),
			r.ScannedAt.Format(time.RFC3339),
			r.Error,
		})
		if err != nil {
			return err
		}
		ow.csvW.Flush()
	default: // text
		status := "NO"
		if r.IsReality {
			status = "YES"
		}
		line := fmt.Sprintf("%s:%d\treality=%s\tfp=%s\tsni=%s\tcountry=%s\tasn=%s\tlatency=%dms",
			r.IP, r.Port, status, r.Fingerprint, r.ServerName, r.Country, r.ASN, r.Latency)
		if r.Error != "" {
			line += "\terror=" + r.Error
		}
		_, err := fmt.Fprintln(ow.file, line)
		return err
	}
	return nil
}

// Close finalises and closes the output (flushes JSON array if needed).
func (ow *OutputWriter) Close() error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	if ow.format == "json" {
		enc := json.NewEncoder(ow.file)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ow.results); err != nil {
			return err
		}
	} else if ow.format == "csv" {
		ow.csvW.Flush()
	}

	if ow.file != os.Stdout {
		return ow.file.Close()
	}
	return nil
}
