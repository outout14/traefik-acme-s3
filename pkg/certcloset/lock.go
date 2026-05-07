package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const lockKey = "state/lock.json"
const lockTTL = 5 * time.Minute

type lockRecord struct {
	Hostname   string    `json:"hostname"`
	AcquiredAt time.Time `json:"acquired_at"`
}

// AcquireLock attempts to take a process-level distributed lock stored in S3.
// Returns an error when another instance holds a fresh lock (younger than lockTTL).
// Stale locks are overwritten. This uses a read-then-write pattern; the race window
// is acceptable for single-instance deployments with rolling-deploy overlap protection.
func (c *CertCloset) AcquireLock() error {
	ctx := context.TODO()

	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(lockKey),
	})
	if err == nil {
		var rec lockRecord
		_ = json.NewDecoder(out.Body).Decode(&rec)
		if age := time.Since(rec.AcquiredAt); age < lockTTL {
			return fmt.Errorf("another instance holds the lock (host=%s, age=%s) — skipping run",
				rec.Hostname, age.Round(time.Second))
		}
		// Stale lock — overwrite below.
	} else if !IsErrNotFound(err) {
		return fmt.Errorf("read lock: %w", err)
	}

	hostname, _ := os.Hostname()
	data, _ := json.Marshal(&lockRecord{Hostname: hostname, AcquiredAt: time.Now()})
	_, err = c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(lockKey),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("write lock: %w", err)
	}
	return nil
}

// ReleaseLock removes the S3 lock object.
// Errors are silently ignored — the lock expires automatically via lockTTL.
func (c *CertCloset) ReleaseLock() {
	_, _ = c.s3.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(lockKey),
	})
}
