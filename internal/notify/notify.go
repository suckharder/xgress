// Package notify delivers operational alerts (certificate issuance/renewal
// failures, expiry warnings) to the channels the operator configures: an SMTP
// email and/or a generic JSON webhook. Delivery is best-effort — a failure to
// notify is logged but never blocks the operation that triggered it.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/suckharder/xgress/internal/ssrfguard"
)

// Config is resolved from settings at send time so changes take effect live.
type Config struct {
	WebhookURL string

	EmailTo  string
	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	SMTPFrom string
}

// Enabled reports whether any channel is configured.
func (c Config) Enabled() bool {
	return c.WebhookURL != "" || (c.EmailTo != "" && c.SMTPHost != "")
}

// ConfigProvider returns the current notification config (from the store).
type ConfigProvider func(ctx context.Context) Config

// Dispatcher sends notifications using the current config.
type Dispatcher struct {
	provider ConfigProvider
	log      *slog.Logger
	client   *http.Client
	dialer   *net.Dialer // SSRF-guarded at connect time (webhook + SMTP)
}

// New constructs a Dispatcher. Outbound sinks (webhook, SMTP) dial through an
// SSRF-guarded dialer that re-checks the SSRF policy on the resolved IP at connect
// time, so a DNS-rebinding host that resolved benign at save can't reach loopback /
// the metadata service later (S6).
func New(provider ConfigProvider, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: ssrfguard.DialControl}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dialer.DialContext
	return &Dispatcher{
		provider: provider, log: log, dialer: dialer,
		client: &http.Client{Timeout: 10 * time.Second, Transport: tr},
	}
}

// Notify delivers a message to all configured channels (best-effort).
func (d *Dispatcher) Notify(ctx context.Context, level, subject, body string) {
	cfg := d.provider(ctx)
	if !cfg.Enabled() {
		return
	}
	if cfg.WebhookURL != "" {
		if err := d.sendWebhook(ctx, cfg, level, subject, body); err != nil {
			d.log.Warn("notify webhook failed", "err", err)
		}
	}
	if cfg.EmailTo != "" && cfg.SMTPHost != "" {
		if err := d.sendEmail(cfg, subject, body); err != nil {
			d.log.Warn("notify email failed", "err", err)
		}
	}
}

// Test sends a test notification with the provided (not-yet-saved) config so the
// UI can verify settings. Returns the first channel error, if any.
func (d *Dispatcher) Test(ctx context.Context, cfg Config) error {
	if !cfg.Enabled() {
		return fmt.Errorf("no notification channel configured")
	}
	if cfg.WebhookURL != "" {
		if err := d.sendWebhook(ctx, cfg, "info", "xgress test notification", "This is a test from xgress."); err != nil {
			return fmt.Errorf("webhook: %w", err)
		}
	}
	if cfg.EmailTo != "" && cfg.SMTPHost != "" {
		if err := d.sendEmail(cfg, "xgress test notification", "This is a test from xgress."); err != nil {
			return fmt.Errorf("email: %w", err)
		}
	}
	return nil
}

func (d *Dispatcher) sendWebhook(ctx context.Context, cfg Config, level, subject, body string) error {
	payload, _ := json.Marshal(map[string]string{
		"level": level, "subject": subject, "body": body, "source": "xgress",
		"time": time.Now().UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func (d *Dispatcher) sendEmail(cfg Config, subject, body string) error {
	port := cfg.SMTPPort
	if port == "" {
		port = "587"
	}
	from := cfg.SMTPFrom
	if from == "" {
		from = cfg.SMTPUser
	}
	addr := cfg.SMTPHost + ":" + port
	msg := buildMessage(from, cfg.EmailTo, subject, body)

	// Dial through the SSRF-guarded dialer (S6), then drive SMTP manually — this
	// mirrors smtp.SendMail (STARTTLS when offered, PlainAuth over TLS) but lets us
	// enforce the connect-time SSRF check that SendMail's internal net.Dial can't.
	conn, err := d.dialer.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.SMTPHost}); err != nil {
			return err
		}
	}
	if cfg.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range strings.Split(cfg.EmailTo, ",") {
		if rcpt = strings.TrimSpace(rcpt); rcpt != "" {
			if err := c.Rcpt(rcpt); err != nil {
				return err
			}
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
