package certcloset

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rs/zerolog/log"
)

const lockKey = "state/lock.json"
const lockTTL = 5 * time.Minute

type lockRecord struct {
	Hostname   string    `json:"hostname"`
	OwnerID    string    `json:"owner_id"`
	AcquiredAt time.Time `json:"acquired_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func newLockOwnerID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate lock owner id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (c *CertCloset) currentLockToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lockToken
}

func (c *CertCloset) setLockToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lockToken = token
}

func (c *CertCloset) loadLock(ctx context.Context) (*lockRecord, string, bool, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(lockKey),
	})
	if err != nil {
		if IsErrNotFound(err) {
			return nil, "", false, nil
		}
		return nil, "", false, fmt.Errorf("read lock: %w", err)
	}
	defer out.Body.Close()

	etag := ""
	if out.ETag != nil {
		etag = *out.ETag
	}

	var rec lockRecord
	if decErr := json.NewDecoder(out.Body).Decode(&rec); decErr != nil {
		log.Warn().Err(decErr).Msg("Unable to decode lock record, treating lock as stale")
		return &lockRecord{}, etag, true, nil
	}
	if rec.ExpiresAt.IsZero() && !rec.AcquiredAt.IsZero() {
		rec.ExpiresAt = rec.AcquiredAt.Add(lockTTL)
	}
	return &rec, etag, true, nil
}

func (c *CertCloset) putLock(ctx context.Context, rec *lockRecord, etag string, requireMissing bool) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal lock: %w", err)
	}
	input := &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(lockKey),
		Body:   bytes.NewReader(data),
	}
	if requireMissing {
		input.IfNoneMatch = strPtr("*")
	} else if etag != "" {
		input.IfMatch = &etag
	}
	_, err = c.s3.PutObject(ctx, input)
	if err != nil {
		if isErrHTTPStatus(err, http.StatusPreconditionFailed) || isErrHTTPStatus(err, http.StatusConflict) {
			return fmt.Errorf("lock changed while updating: %w", err)
		}
		return fmt.Errorf("write lock: %w", err)
	}
	return nil
}

// AcquireLock attempts to take a process-level distributed lock stored in S3.
// Returns an error when another instance holds a fresh lock. Stale locks are
// overwritten conditionally so concurrent acquirers do not silently clobber each other.
func (c *CertCloset) AcquireLock() error {
	if c.currentLockToken() != "" {
		return fmt.Errorf("this instance already holds the lock")
	}

	ctx := context.TODO()
	rec, etag, exists, err := c.loadLock(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	if exists && now.Before(rec.ExpiresAt) {
		return fmt.Errorf("another instance holds the lock (host=%s, expires_in=%s) — skipping run",
			rec.Hostname, time.Until(rec.ExpiresAt).Round(time.Second))
	}

	hostname, _ := os.Hostname()
	token, err := newLockOwnerID()
	if err != nil {
		return err
	}
	newRec := &lockRecord{
		Hostname:   hostname,
		OwnerID:    token,
		AcquiredAt: now,
		ExpiresAt:  now.Add(lockTTL),
	}
	if err := c.putLock(ctx, newRec, etag, !exists); err != nil {
		return err
	}
	c.setLockToken(token)
	return nil
}

// RefreshLock extends the current process lock expiry.
func (c *CertCloset) RefreshLock() error {
	token := c.currentLockToken()
	if token == "" {
		return fmt.Errorf("this instance does not hold the lock")
	}

	ctx := context.TODO()
	rec, etag, exists, err := c.loadLock(ctx)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("lock disappeared")
	}
	if rec.OwnerID != token {
		return fmt.Errorf("lock is owned by another instance")
	}
	rec.ExpiresAt = time.Now().Add(lockTTL)
	return c.putLock(ctx, rec, etag, false)
}

// ReleaseLock removes the S3 lock object only if this process still owns it.
// Errors are logged; the lock also expires automatically via lockTTL.
func (c *CertCloset) ReleaseLock() {
	token := c.currentLockToken()
	if token == "" {
		return
	}
	defer c.setLockToken("")

	ctx := context.TODO()
	rec, etag, exists, err := c.loadLock(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Unable to read distributed lock before release")
		return
	}
	if !exists {
		return
	}
	if rec.OwnerID != token {
		log.Warn().Str("host", rec.Hostname).Msg("Not releasing distributed lock owned by another instance")
		return
	}

	input := &s3.DeleteObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(lockKey),
	}
	if etag != "" {
		input.IfMatch = &etag
	}
	_, err = c.s3.DeleteObject(ctx, input)
	if err != nil {
		log.Warn().Err(err).Msg("Unable to release distributed lock")
	}
}
