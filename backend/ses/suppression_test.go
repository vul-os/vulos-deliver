package ses

import (
	"testing"
)

func TestMemorySuppressionList_AddAndCheck(t *testing.T) {
	sl := NewMemorySuppressionList()

	if err := sl.Add("User@Example.COM", ReasonBounce); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// IsSuppressed is case-insensitive.
	ok, entry, err := sl.IsSuppressed("user@example.com")
	if err != nil {
		t.Fatalf("IsSuppressed: %v", err)
	}
	if !ok {
		t.Error("expected address to be suppressed")
	}
	if entry.Reason != ReasonBounce {
		t.Errorf("Reason = %q, want %q", entry.Reason, ReasonBounce)
	}
}

func TestMemorySuppressionList_NotSuppressed(t *testing.T) {
	sl := NewMemorySuppressionList()
	ok, _, err := sl.IsSuppressed("clean@example.com")
	if err != nil {
		t.Fatalf("IsSuppressed: %v", err)
	}
	if ok {
		t.Error("address should not be suppressed")
	}
}

func TestMemorySuppressionList_Remove(t *testing.T) {
	sl := NewMemorySuppressionList()
	_ = sl.Add("gone@example.com", ReasonManual)
	_ = sl.Remove("gone@example.com")

	ok, _, _ := sl.IsSuppressed("gone@example.com")
	if ok {
		t.Error("address should no longer be suppressed after Remove")
	}
}

func TestMemorySuppressionList_Count(t *testing.T) {
	sl := NewMemorySuppressionList()
	if sl.Count() != 0 {
		t.Errorf("initial count = %d, want 0", sl.Count())
	}
	_ = sl.Add("a@example.com", ReasonBounce)
	_ = sl.Add("b@example.com", ReasonComplaint)
	if sl.Count() != 2 {
		t.Errorf("count = %d, want 2", sl.Count())
	}
	_ = sl.Remove("a@example.com")
	if sl.Count() != 1 {
		t.Errorf("count = %d after remove, want 1", sl.Count())
	}
}

func TestMemorySuppressionList_IdempotentAdd(t *testing.T) {
	sl := NewMemorySuppressionList()
	_ = sl.Add("dup@example.com", ReasonBounce)
	_ = sl.Add("dup@example.com", ReasonComplaint) // update reason

	_, entry, _ := sl.IsSuppressed("dup@example.com")
	if entry.Reason != ReasonComplaint {
		t.Errorf("Reason = %q, want %q after update", entry.Reason, ReasonComplaint)
	}
	if sl.Count() != 1 {
		t.Errorf("count = %d after duplicate add, want 1", sl.Count())
	}
}

func TestMemorySuppressionList_EmptyEmail(t *testing.T) {
	sl := NewMemorySuppressionList()
	err := sl.Add("", ReasonBounce)
	if err == nil {
		t.Error("expected error adding empty email")
	}
}

func TestSuppressionListImplementsInterface(t *testing.T) {
	var _ SuppressionList = (*MemorySuppressionList)(nil)
}
