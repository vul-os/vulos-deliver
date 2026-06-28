package ses

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// SuppressionReason explains why an address is on the suppression list.
type SuppressionReason string

const (
	// ReasonBounce suppresses on permanent delivery failure.
	ReasonBounce SuppressionReason = "bounce"

	// ReasonComplaint suppresses on a spam/abuse complaint (FBL).
	ReasonComplaint SuppressionReason = "complaint"

	// ReasonManual suppresses on explicit operator action.
	ReasonManual SuppressionReason = "manual"
)

// SuppressionEntry records a suppressed address and why.
type SuppressionEntry struct {
	Email        string
	Reason       SuppressionReason
	SuppressedAt time.Time
}

// SuppressionList stores addresses that must never receive outbound mail.
//
// The default in-memory implementation (MemorySuppressionList) is suitable for
// development and single-instance deployments. Replace it with a persistent,
// shared backend (Postgres, Redis, …) for multi-instance production use.
type SuppressionList interface {
	// Add records an address on the list. Duplicate adds are idempotent;
	// the reason is updated if the address is already suppressed.
	Add(email string, reason SuppressionReason) error

	// IsSuppressed returns (true, entry, nil) if the address is suppressed.
	// The email comparison is case-insensitive.
	IsSuppressed(email string) (bool, SuppressionEntry, error)

	// Remove lifts the suppression for an address (e.g. after re-subscribe
	// with explicit consent). No-op if the address is not suppressed.
	Remove(email string) error

	// Count returns the number of currently suppressed addresses.
	Count() int
}

// MemorySuppressionList is an in-memory SuppressionList backed by a sync.Map.
// It is goroutine-safe but does NOT persist across process restarts.
type MemorySuppressionList struct {
	mu      sync.RWMutex
	entries map[string]SuppressionEntry
}

// NewMemorySuppressionList allocates a new empty MemorySuppressionList.
func NewMemorySuppressionList() *MemorySuppressionList {
	return &MemorySuppressionList{
		entries: make(map[string]SuppressionEntry),
	}
}

// Add implements SuppressionList.
func (m *MemorySuppressionList) Add(email string, reason SuppressionReason) error {
	email = normalize(email)
	if email == "" {
		return fmt.Errorf("ses/suppression: empty email address")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[email] = SuppressionEntry{
		Email:        email,
		Reason:       reason,
		SuppressedAt: time.Now(),
	}
	return nil
}

// IsSuppressed implements SuppressionList.
func (m *MemorySuppressionList) IsSuppressed(email string) (bool, SuppressionEntry, error) {
	email = normalize(email)
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.entries[email]
	return ok, entry, nil
}

// Remove implements SuppressionList.
func (m *MemorySuppressionList) Remove(email string) error {
	email = normalize(email)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, email)
	return nil
}

// Count implements SuppressionList.
func (m *MemorySuppressionList) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

func normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
