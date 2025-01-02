package gomon

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "Valid configuration",
			config: Config{
				URL:            "https://example.com",
				Method:         http.MethodGet,
				RequestTimeout: 5 * time.Second,
				UpStatusCodes:  []int{200},
			},
			wantErr: false,
		},
		{
			name: "Invalid URL",
			config: Config{
				URL:            "invalid-url",
				Method:         http.MethodGet,
				RequestTimeout: 5 * time.Second,
				UpStatusCodes:  []int{200},
			},
			wantErr: true,
		},
		{
			name: "Missing HTTP method",
			config: Config{
				URL:            "https://example.com",
				RequestTimeout: 5 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "Negative timeout",
			config: Config{
				URL:            "https://example.com",
				Method:         http.MethodGet,
				RequestTimeout: -5 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMonitor(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMonitor() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{
			name:    "Valid URL",
			rawURL:  "https://example.com",
			want:    "https://example.com",
			wantErr: false,
		},
		{
			name:    "Invalid URL without scheme",
			rawURL:  "example.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Invalid URL without host",
			rawURL:  "https://",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeURL(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sanitizeURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMonitor_Check(t *testing.T) {
	tests := []struct {
		name    string
		monitor *Monitor
		ctx     context.Context
		wantErr bool
	}{
		{
			name: "Valid site check",
			monitor: &Monitor{
				client: &http.Client{},
				config: Config{
					URL:            "https://example.com",
					Method:         http.MethodGet,
					RequestTimeout: 5 * time.Second,
					UpStatusCodes:  []int{200},
				},
			},
			ctx:     context.Background(),
			wantErr: false,
		},
		{
			name: "Invalid site check (non-existent URL)",
			monitor: &Monitor{
				client: &http.Client{},
				config: Config{
					URL:            "https://nonexistent.example.com",
					Method:         http.MethodGet,
					RequestTimeout: 5 * time.Second,
					UpStatusCodes:  []int{200},
				},
			},
			ctx:     context.Background(),
			wantErr: true,
		},
		{
			name: "Empty URL",
			monitor: &Monitor{
				client: &http.Client{},
				config: Config{
					URL:            "",
					Method:         http.MethodGet,
					RequestTimeout: 5 * time.Second,
					UpStatusCodes:  []int{200},
				},
			},
			ctx:     context.Background(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.monitor.Check(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got == nil {
				t.Errorf("Check() result is nil")
			}
		})
	}
}
