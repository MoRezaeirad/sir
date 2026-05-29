package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ingestReq builds a /v1/detections POST for the canonical test event.
func ingestReq(t *testing.T) *http.Request {
	t.Helper()
	body, _ := json.Marshal(testEvent())
	return httptest.NewRequest(http.MethodPost, "/v1/detections", bytes.NewReader(body))
}

// --- ingest token auth ---

func TestRelay_Ingest_NoTokenConfigured_Accepts(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{})
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, ingestReq(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("unauthenticated mode: status = %d, want 200", rec.Code)
	}
}

func TestRelay_Ingest_TokenConfigured_RejectsMissingAndWrong(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{IngestToken: "s3cret"})
	h := r.Handler()

	// Missing token.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ingestReq(t))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token: status = %d, want 401", rec.Code)
	}

	// Wrong token.
	req := ingestReq(t)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", rec.Code)
	}
}

func TestRelay_Ingest_TokenConfigured_AcceptsCorrect(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{IngestToken: "s3cret"})
	h := r.Handler()

	// Bearer form.
	req := ingestReq(t)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("correct bearer token: status = %d, want 200", rec.Code)
	}

	// X-Sir-Relay-Token form.
	req = ingestReq(t)
	req.Header.Set(relayTokenHeader, "s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("correct header token: status = %d, want 200", rec.Code)
	}
}

func TestRelay_Stats_TokenConfigured_RequiresToken(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{IngestToken: "s3cret"})
	h := r.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("stats without token: status = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("stats with token: status = %d, want 200", rec.Code)
	}
}

// --- Slack interaction signature ---

func signedInteraction(secret, body string, ts time.Time) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/slack/interactions", strings.NewReader(body))
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + tsStr + ":" + body))
	req.Header.Set("X-Slack-Request-Timestamp", tsStr)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	return req
}

func interactionBody() string {
	payload := map[string]any{
		"actions": []map[string]any{{"value": "sir explain --last"}},
	}
	raw, _ := json.Marshal(payload)
	return url.Values{"payload": {string(raw)}}.Encode()
}

func TestRelay_Interaction_NoSecret_Accepts(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/slack/interactions", strings.NewReader(interactionBody()))
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("no-secret interaction: status = %d, want 200", rec.Code)
	}
}

func TestRelay_Interaction_SecretConfigured_RejectsUnsignedAndForged(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{SlackSigningSecret: "shh"})
	h := r.Handler()

	// Unsigned.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/slack/interactions", strings.NewReader(interactionBody())))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unsigned interaction: status = %d, want 401", rec.Code)
	}

	// Forged signature (signed with the wrong secret).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedInteraction("wrong-secret", interactionBody(), time.Now()))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("forged signature: status = %d, want 401", rec.Code)
	}

	// Stale timestamp (replay), correctly signed but outside the skew window.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedInteraction("shh", interactionBody(), time.Now().Add(-1*time.Hour)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("stale signed interaction: status = %d, want 401", rec.Code)
	}
}

func TestRelay_Interaction_SecretConfigured_AcceptsValidSignature(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{SlackSigningSecret: "shh"})
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, signedInteraction("shh", interactionBody(), time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid signature: status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sir explain --last") {
		t.Errorf("valid interaction should echo the command, got: %s", rec.Body.String())
	}
}

// --- oversized payload ---

func TestRelay_Ingest_OversizedPayloadRejected(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{})
	// A body larger than maxIngestBytes is truncated by the LimitReader, so it
	// no longer parses as JSON -> 400.
	huge := `{"detection_id":"x","blob":"` + strings.Repeat("a", maxIngestBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/detections", strings.NewReader(huge))
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized ingest: status = %d, want 400", rec.Code)
	}
}

// --- rate limiting ---

func TestRelay_Ingest_RateLimited(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{RateLimit: 3, RateWindow: time.Minute})
	h := r.Handler()
	statuses := make([]int, 0, 5)
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestReq(t))
		statuses = append(statuses, rec.Code)
	}
	// First 3 within budget, then 429.
	got429 := false
	for i, code := range statuses {
		if i < 3 && code == http.StatusTooManyRequests {
			t.Errorf("request %d rate-limited too early (status %d)", i, code)
		}
		if code == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatalf("expected at least one 429 after exceeding the limit, got %v", statuses)
	}
}

// --- signature helper unit coverage ---

func TestVerifySlackSignature(t *testing.T) {
	secret := "topsecret"
	body := []byte("v0body")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	good := "v0=" + hex.EncodeToString(mac.Sum(nil))

	if !verifySlackSignature(secret, ts, good, body, time.Now()) {
		t.Error("valid signature rejected")
	}
	if verifySlackSignature(secret, ts, "v0=deadbeef", body, time.Now()) {
		t.Error("bad signature accepted")
	}
	if verifySlackSignature(secret, ts, good, []byte("tampered"), time.Now()) {
		t.Error("signature accepted over a tampered body")
	}
	if verifySlackSignature(secret, "", good, body, time.Now()) {
		t.Error("missing timestamp accepted")
	}
	if verifySlackSignature("", ts, good, body, time.Now()) == false {
		t.Error("empty secret should skip verification (return true)")
	}
	// Stale timestamp outside the skew window.
	staleTs := strconv.FormatInt(time.Now().Add(-2*slackMaxSkew).Unix(), 10)
	mac2 := hmac.New(sha256.New, []byte(secret))
	mac2.Write([]byte("v0:" + staleTs + ":"))
	mac2.Write(body)
	staleSig := "v0=" + hex.EncodeToString(mac2.Sum(nil))
	if verifySlackSignature(secret, staleTs, staleSig, body, time.Now()) {
		t.Error("stale (replayed) signature accepted")
	}
}
