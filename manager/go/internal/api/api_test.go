package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FROSTY-MUG/jocky/manager/go/internal/store"
	"github.com/FROSTY-MUG/jocky/manager/go/internal/types"
)

func TestAPI_HealthAndAuditVerify(t *testing.T) {
	s := store.NewStore()
	srv := NewServer(s)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
	if res["status"] != "healthy" {
		t.Errorf("expected status healthy, got %v", res["status"])
	}

	// Audit verify endpoint
	vReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	vRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(vRec, vReq)

	if vRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", vRec.Code)
	}
	var vRes map[string]any
	if err := json.Unmarshal(vRec.Body.Bytes(), &vRes); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if vRes["verified"] != true {
		t.Errorf("expected verified=true, got %v", vRes["verified"])
	}
}

func TestAPI_ListAgentsAndCreateJob(t *testing.T) {
	s := store.NewStore()
	srv := NewServer(s)

	// GET /api/v1/agents
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// POST /api/v1/jobs
	jobReq := map[string]any{
		"ticket_id":     "INC-9999",
		"script_id":     "scr-byovd",
		"requested_by":  "dfir-lead",
		"target_agents": []string{"agt-win-01"},
		"ttl_minutes":   20,
	}
	body, _ := json.Marshal(jobReq)
	jReq := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	jReq.Header.Set("Content-Type", "application/json")
	jRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(jRec, jReq)

	if jRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", jRec.Code, jRec.Body.String())
	}

	var createdJob types.ForensicJob
	if err := json.Unmarshal(jRec.Body.Bytes(), &createdJob); err != nil {
		t.Fatalf("failed to decode created job: %v", err)
	}
	if createdJob.TicketID != "INC-9999" {
		t.Errorf("expected INC-9999, got %s", createdJob.TicketID)
	}
}

func TestAPI_VerifyJKMHeader(t *testing.T) {
	s := store.NewStore()
	srv := NewServer(s)

	// Valid 64-byte payload with 'JKM\x01'
	validPayload := make([]byte, 64)
	validPayload[0] = 'J'
	validPayload[1] = 'K'
	validPayload[2] = 'M'
	validPayload[3] = 0x01

	req := httptest.NewRequest(http.MethodPost, "/api/v1/verify-jkm", bytes.NewReader(validPayload))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Invalid magic bytes
	invalidPayload := make([]byte, 64)
	copy(invalidPayload, []byte("BAD!"))
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/verify-jkm", bytes.NewReader(invalidPayload))
	badRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badRec, badReq)

	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", badRec.Code)
	}
}
