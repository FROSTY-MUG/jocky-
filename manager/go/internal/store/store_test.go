package store

import (
	"testing"

	"github.com/FROSTY-MUG/jocky/manager/go/internal/types"
)

func TestStore_AuditChainIntegrity(t *testing.T) {
	s := NewStore()

	// Initial chain should be intact
	valid, count, _, err := s.VerifyAuditChain()
	if err != nil || !valid {
		t.Fatalf("expected valid audit chain, got valid=%v, err=%v", valid, err)
	}
	if count < 1 {
		t.Fatalf("expected at least 1 audit entry, got %d", count)
	}

	// Append an event
	s.AppendAudit("operator-01", "QUERY_FLEET", "all", "test-payload")

	valid, newCount, _, err := s.VerifyAuditChain()
	if err != nil || !valid {
		t.Fatalf("expected valid audit chain after append, got err=%v", err)
	}
	if newCount != count+1 {
		t.Fatalf("expected count %d, got %d", count+1, newCount)
	}
}

func TestStore_AuditChainTamperDetection(t *testing.T) {
	s := NewStore()
	s.AppendAudit("op1", "ACTION1", "tgt1", "data1")
	s.AppendAudit("op2", "ACTION2", "tgt2", "data2")

	// Tamper with an entry in the middle
	s.mu.Lock()
	s.auditLogs[1].PrevHash = "tampered_hash_00000000000000000000000000000000000000000000000000"
	s.mu.Unlock()

	valid, _, _, err := s.VerifyAuditChain()
	if valid || err == nil {
		t.Fatalf("expected chain verification to fail on tampered log, but it passed!")
	}
}

func TestStore_CreateJobAndConsent(t *testing.T) {
	s := NewStore()

	job, err := s.CreateJob("INC-2026-9901", "scr-byovd", "lead-forensic-analyst", []string{"agt-win-01", "agt-win-02"}, 30)
	if err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	if job.TicketID != "INC-2026-9901" {
		t.Errorf("expected ticket ID INC-2026-9901, got %s", job.TicketID)
	}
	if job.ConsentToken.TokenID == "" {
		t.Errorf("expected generated consent token, got empty")
	}
	if len(job.ConsentToken.ScopeTargets) != 2 {
		t.Errorf("expected 2 targets in consent scope, got %d", len(job.ConsentToken.ScopeTargets))
	}
	if job.ConsentToken.Signature == "" {
		t.Errorf("expected non-empty signature on consent token")
	}

	// Verify agent status update
	updated, err := s.UpdateAgentStatus("agt-win-01", types.StateQuarantined, "Isolation test")
	if err != nil {
		t.Fatalf("failed to update status: %v", err)
	}
	if updated.State != types.StateQuarantined {
		t.Errorf("expected quarantined, got %s", updated.State)
	}
}
