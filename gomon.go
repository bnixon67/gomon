package gomon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config defines the configuration to monitor a site.
type Config struct {
	URL                string
	Method             string
	RequestTimeout     time.Duration
	IgnoreCert         bool
	DontFollowRedirect bool
	UpStatusCodes      []int
	//RequestBody string
	Headers http.Header
}

// Monitor is a client used to monitor a site.
type Monitor struct {
	client *http.Client
	config Config
}

// CheckResult stores the results of a site check.
type CheckResult struct {
	URL        string
	StatusCode int
	Start      time.Time
	End        time.Time
	CertInfo   *CertInfo
}

// CertInfo contains certificate details for HTTPS checks.
type CertInfo struct {
	Subject   string
	Issuer    string
	ValidFrom time.Time
	ValidTo   time.Time
	DNSNames  []string
	IsValid   bool
	ErrorMsg  string
}

// noRedirect disables HTTP redirects.
func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// NewMonitor creates and configures a new Site monitor instance.
func NewMonitor(config Config) (*Monitor, error) {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}

	if len(config.UpStatusCodes) == 0 {
		config.UpStatusCodes = []int{200, 201}
	}

	if config.Method == "" {
		return nil, fmt.Errorf("missing HTTP method")
	}

	if config.RequestTimeout < 0 {
		return nil, fmt.Errorf("negative timeout")
	}

	validURL, err := sanitizeURL(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	config.URL = validURL

	client := &http.Client{
		Timeout: config.RequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.IgnoreCert,
			},
		},
	}

	if config.DontFollowRedirect {
		client.CheckRedirect = noRedirect
	}

	return &Monitor{client: client, config: config}, nil
}

// sanitizeURL validates and returns a sanitized URL string.
func sanitizeURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	if parsedURL.Scheme == "" {
		return "", fmt.Errorf("missing scheme %q", rawURL)
	}

	if parsedURL.Host == "" {
		return "", fmt.Errorf("missing host %q", rawURL)
	}

	return parsedURL.String(), nil
}

// isSuccessStatus determines if status code is acceptable based on config.
func (m *Monitor) isSuccessStatus(code int) bool {
	if len(m.config.UpStatusCodes) == 0 {
		return code >= 200 && code < 300
	}

	for _, validCode := range m.config.UpStatusCodes {
		if code == validCode {
			return true
		}
	}

	return false
}

// Check executes an HTTP request to the configured URL and returns the result.
func (m *Monitor) Check(ctx context.Context) (*CheckResult, error) {
	result := CheckResult{URL: m.config.URL}

	req, err := http.NewRequestWithContext(ctx, m.config.Method, m.config.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %q: %w", m.config.URL, err)
	}

	// Add cache-busting headers to the request
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")
	req.URL.RawQuery = fmt.Sprintf("nocache=%d", time.Now().UnixNano())

	result.Start = time.Now()
	resp, err := m.client.Do(req)
	result.End = time.Now()

	if err != nil {
		return nil, fmt.Errorf("failed to send request for %q: %w", m.config.URL, err)
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Discard response body
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body for %q: %w", m.config.URL, err)
	}

	// Process certificate information
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		// extract host from response to handle redirects
		result.CertInfo = certInfo(resp.TLS, resp.Request.URL.Hostname())
	}

	return &result, nil
}

// certInfo extracts certificate details and verifies the validity.
func certInfo(tlsState *tls.ConnectionState, host string) *CertInfo {
	cert := tlsState.PeerCertificates[0]
	certInfo := &CertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		ValidFrom: cert.NotBefore,
		ValidTo:   cert.NotAfter,
		DNSNames:  cert.DNSNames,
		IsValid:   true,
	}

	// Check certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		certInfo.IsValid = false
		certInfo.ErrorMsg = fmt.Sprintf("certificate not yet valid: %s", cert.NotBefore)
		return certInfo
	}
	if now.After(cert.NotAfter) {
		certInfo.IsValid = false
		certInfo.ErrorMsg = fmt.Sprintf("certificate has expired: %s", cert.NotAfter)
		return certInfo
	}

	// Perform standard x509 verification
	roots, err := x509.SystemCertPool()
	if err != nil {
		certInfo.IsValid = false
		certInfo.ErrorMsg = fmt.Sprintf("error loading system root certificates: %v", err)
		return certInfo
	}

	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range tlsState.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if _, err := cert.Verify(opts); err != nil {
		certInfo.IsValid = false
		certInfo.ErrorMsg = fmt.Sprintf("hostname verification failed: %v", err)
	}

	return certInfo
}

// String implements the Stringer interface for MonitorResult.
func (result *CheckResult) String() string {
	const timeFormat = time.DateTime

	var builder strings.Builder

	builder.WriteString("Website: ")
	builder.WriteString(result.URL)
	builder.WriteString("\n")

	builder.WriteString("Status: ")
	builder.WriteString(strconv.Itoa(result.StatusCode))
	builder.WriteString(" (")
	builder.WriteString(http.StatusText(result.StatusCode)) // String status code
	builder.WriteString(")\n")

	builder.WriteString("Start: ")
	builder.WriteString(result.Start.Format(timeFormat))
	builder.WriteString("\n")

	builder.WriteString("  End: ")
	builder.WriteString(result.End.Format(timeFormat))
	builder.WriteString("\n")

	builder.WriteString("Duration: ")
	builder.WriteString(result.End.Sub(result.Start).String())
	builder.WriteString("\n")

	if result.CertInfo != nil {
		builder.WriteString("Certificate Info:\n")
		builder.WriteString("  Valid: ")
		builder.WriteString(strconv.FormatBool(result.CertInfo.IsValid))
		builder.WriteString("\n")

		if result.CertInfo.ErrorMsg != "" {
			builder.WriteString("  Error: ")
			builder.WriteString(result.CertInfo.ErrorMsg)
			builder.WriteString("\n")
		}

		builder.WriteString("  From ")
		builder.WriteString(result.CertInfo.ValidFrom.Format(timeFormat))
		builder.WriteString(" to ")
		builder.WriteString(result.CertInfo.ValidTo.Format(timeFormat))
		builder.WriteString("\n")
	}

	return builder.String()
}
