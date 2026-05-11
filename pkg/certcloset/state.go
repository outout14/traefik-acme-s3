package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	failureStateKey  = "state/failures.json"
	rolloverPrefix   = "state/rollover/"
	pendingKeyPrefix = "state/pending/"
	acmeUserKey      = "state/acme_user.json.enc"
)

// FailureState tracks the last failure time per domain.
type FailureState struct {
	LastFailure map[string]string `json:"last_failure"`
}

// RolloverPhase is the current step of a TLSA rollover.
type RolloverPhase string

const (
	RolloverPhasePrePublishing RolloverPhase = "pre-publishing" // new TLSA published, waiting TTL
	RolloverPhaseCertSwitched  RolloverPhase = "cert-switched"  // cert stored, waiting sync lag
)

// RolloverState persists the TLSA rollover progress for one domain.
type RolloverState struct {
	Phase          RolloverPhase `json:"phase"`
	OldTLSAHex     string        `json:"old_tlsa_hex"` // empty if no prior cert or wildcard
	NewTLSAHex     string        `json:"new_tlsa_hex"`
	PhaseStartedAt time.Time     `json:"phase_started_at"`
	TLSATTLSeconds int           `json:"tlsa_ttl_seconds"`
	SyncLagSeconds int           `json:"sync_lag_seconds"`
}

// LoadFailureState reads the failure state from S3.
// Returns an empty state when the object does not exist yet.
func (c *CertCloset) LoadFailureState() (*FailureState, error) {
	out, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(failureStateKey),
	})
	if err != nil {
		if IsErrNotFound(err) {
			return &FailureState{LastFailure: make(map[string]string)}, nil
		}
		return nil, fmt.Errorf("load failure state: %w", err)
	}
	defer out.Body.Close()
	var s FailureState
	if err := json.NewDecoder(out.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode failure state: %w", err)
	}
	if s.LastFailure == nil {
		s.LastFailure = make(map[string]string)
	}
	return &s, nil
}

// StoreFailureState writes the failure state to S3.
func (c *CertCloset) StoreFailureState(state *FailureState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal failure state: %w", err)
	}
	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(failureStateKey),
		Body:   bytes.NewReader(data),
	})
	return err
}

// LoadACMEUser reads and decrypts the persisted ACME account user JSON from S3.
// exists=false means no S3-backed ACME user has been stored yet.
func (c *CertCloset) LoadACMEUser() ([]byte, bool, error) {
	out, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(acmeUserKey),
	})
	if err != nil {
		if IsErrNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("load ACME user: %w", err)
	}
	defer out.Body.Close()

	encrypted, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read ACME user: %w", err)
	}
	plain, err := decryptAES(c.deriveKey(), encrypted)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt ACME user: %w", err)
	}
	return plain, true, nil
}

// StoreACMEUser encrypts and writes the ACME account user JSON to S3.
func (c *CertCloset) StoreACMEUser(data []byte) error {
	encrypted, err := encryptAES(c.deriveKey(), data)
	if err != nil {
		return fmt.Errorf("encrypt ACME user: %w", err)
	}
	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(acmeUserKey),
		Body:   bytes.NewReader(encrypted),
	})
	return err
}

// StoreACMEUserIfNotExists encrypts and writes the ACME user only when no S3
// object exists yet. Returns stored=false if the object already exists.
// Uses HeadObject+PutObject; the TOCTOU race window is acceptable because the
// ACME user is written only once.
func (c *CertCloset) StoreACMEUserIfNotExists(data []byte) (bool, error) {
	encrypted, err := encryptAES(c.deriveKey(), data)
	if err != nil {
		return false, fmt.Errorf("encrypt ACME user: %w", err)
	}
	_, err = c.s3.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(acmeUserKey),
	})
	if err == nil {
		return false, nil
	}
	if !IsErrNotFound(err) {
		return false, fmt.Errorf("check ACME user existence: %w", err)
	}
	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    strPtr(acmeUserKey),
		Body:   bytes.NewReader(encrypted),
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadRolloverState returns the rollover state for domain.
// exists=false when no rollover is in progress.
func (c *CertCloset) LoadRolloverState(domain string) (*RolloverState, bool, error) {
	key := rolloverPrefix + domain + ".json"
	out, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &key,
	})
	if err != nil {
		if IsErrNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("load rollover state for %s: %w", domain, err)
	}
	defer out.Body.Close()
	var rs RolloverState
	if err := json.NewDecoder(out.Body).Decode(&rs); err != nil {
		return nil, false, fmt.Errorf("decode rollover state for %s: %w", domain, err)
	}
	return &rs, true, nil
}

// StoreRolloverState persists the rollover state for domain.
func (c *CertCloset) StoreRolloverState(domain string, state *RolloverState) error {
	key := rolloverPrefix + domain + ".json"
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal rollover state: %w", err)
	}
	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &key,
		Body:   bytes.NewReader(data),
	})
	return err
}

// DeleteRolloverState removes the rollover state for domain from S3.
func (c *CertCloset) DeleteRolloverState(domain string) error {
	key := rolloverPrefix + domain + ".json"
	_, err := c.s3.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &key,
	})
	return err
}

// StorePendingKey encrypts and stores a PEM private key in S3.
// Used during TLSA pre-publish rollover: the key is stored before the
// ACME request so the same key can be used to request the certificate
// after the TLSA TTL has elapsed.
func (c *CertCloset) StorePendingKey(domain string, keyPEM []byte) error {
	encrypted, err := encryptAES(c.deriveKey(), keyPEM)
	if err != nil {
		return fmt.Errorf("encrypt pending key: %w", err)
	}
	key := pendingKeyPrefix + domain
	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &key,
		Body:   bytes.NewReader(encrypted),
	})
	return err
}

// LoadPendingKey decrypts and returns the pending PEM private key for domain.
func (c *CertCloset) LoadPendingKey(domain string) ([]byte, error) {
	key := pendingKeyPrefix + domain
	out, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("load pending key for %s: %w", domain, err)
	}
	defer out.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(out.Body); err != nil {
		return nil, fmt.Errorf("read pending key: %w", err)
	}
	plain, err := decryptAES(c.deriveKey(), buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("decrypt pending key: %w", err)
	}
	return plain, nil
}

// DeletePendingKey removes the pending key for domain from S3.
func (c *CertCloset) DeletePendingKey(domain string) error {
	key := pendingKeyPrefix + domain
	_, err := c.s3.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &key,
	})
	return err
}

func strPtr(s string) *string { return &s }
