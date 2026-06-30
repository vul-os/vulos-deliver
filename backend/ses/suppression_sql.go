package ses

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SQLSuppressionList is a durable, shared SuppressionList backed by a SQL
// database (Postgres). Unlike MemorySuppressionList it survives process restarts
// and is shared by every instance pointed at the same database, so a
// hard-bounce/complaint suppression recorded by one instance is honoured by all
// of them — which is essential when many tenants share one SES sending identity.
//
// It uses Postgres-style numbered placeholders ($1, $2). Construct it with
// NewSQLSuppressionList, which creates the backing table if it does not exist.
type SQLSuppressionList struct {
	db    *sql.DB
	table string
}

// NewSQLSuppressionList returns a SQLSuppressionList using the given table name
// (default "ses_suppressions" when empty) and ensures the table exists.
//
// The table schema is:
//
//	CREATE TABLE <table> (
//	    email         TEXT PRIMARY KEY,
//	    reason        TEXT NOT NULL,
//	    suppressed_at TIMESTAMPTZ NOT NULL
//	)
func NewSQLSuppressionList(ctx context.Context, db *sql.DB, table string) (*SQLSuppressionList, error) {
	if db == nil {
		return nil, fmt.Errorf("ses/suppression: nil *sql.DB")
	}
	if table == "" {
		table = "ses_suppressions"
	}
	s := &SQLSuppressionList{db: db, table: table}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLSuppressionList) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			email         TEXT PRIMARY KEY,
			reason        TEXT NOT NULL,
			suppressed_at TIMESTAMPTZ NOT NULL
		)`, s.table))
	if err != nil {
		return fmt.Errorf("ses/suppression: ensure schema: %w", err)
	}
	return nil
}

// Add implements SuppressionList. Idempotent: re-adding updates the reason and
// timestamp.
func (s *SQLSuppressionList) Add(email string, reason SuppressionReason) error {
	email = normalize(email)
	if email == "" {
		return fmt.Errorf("ses/suppression: empty email address")
	}
	_, err := s.db.ExecContext(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (email, reason, suppressed_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (email) DO UPDATE SET
			reason        = EXCLUDED.reason,
			suppressed_at = EXCLUDED.suppressed_at`, s.table),
		email, string(reason), time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("ses/suppression: add %q: %w", email, err)
	}
	return nil
}

// IsSuppressed implements SuppressionList.
func (s *SQLSuppressionList) IsSuppressed(email string) (bool, SuppressionEntry, error) {
	email = normalize(email)
	var (
		reason string
		at     time.Time
	)
	err := s.db.QueryRowContext(context.Background(),
		fmt.Sprintf(`SELECT reason, suppressed_at FROM %s WHERE email = $1`, s.table), email,
	).Scan(&reason, &at)
	if err == sql.ErrNoRows {
		return false, SuppressionEntry{}, nil
	}
	if err != nil {
		return false, SuppressionEntry{}, fmt.Errorf("ses/suppression: lookup %q: %w", email, err)
	}
	return true, SuppressionEntry{
		Email:        email,
		Reason:       SuppressionReason(reason),
		SuppressedAt: at,
	}, nil
}

// Remove implements SuppressionList.
func (s *SQLSuppressionList) Remove(email string) error {
	email = normalize(email)
	_, err := s.db.ExecContext(context.Background(),
		fmt.Sprintf(`DELETE FROM %s WHERE email = $1`, s.table), email)
	if err != nil {
		return fmt.Errorf("ses/suppression: remove %q: %w", email, err)
	}
	return nil
}

// Count implements SuppressionList. Returns 0 on query error (best-effort metric).
func (s *SQLSuppressionList) Count() int {
	var n int
	if err := s.db.QueryRowContext(context.Background(),
		fmt.Sprintf(`SELECT count(*) FROM %s`, s.table)).Scan(&n); err != nil {
		return 0
	}
	return n
}

// compile-time interface check
var _ SuppressionList = (*SQLSuppressionList)(nil)
