package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRenderSessionCSV(t *testing.T) {
	rows := []sessionReportRow{{
		ID:         "sess-1",
		UserID:     "u1",
		Username:   "alice",
		MachineID:  "m1",
		Machine:    "web-01",
		RemoteUser: "root",
		Source:     "ssh",
		StartTime:  "2026-07-23T10:00:00Z",
		EndTime:    "2026-07-23T10:05:00Z",
		Status:     "completed",
	}}

	blob, err := renderSessionCSV(rows)
	if err != nil {
		t.Fatalf("renderSessionCSV failed: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(blob))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv parse failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(records))
	}
	if got := strings.Join(records[0], ","); got != "id,user_id,username,machine_id,machine,remote_user,source,start_time,end_time,status" {
		t.Fatalf("unexpected header row: %s", got)
	}
	if records[1][0] != "sess-1" || records[1][2] != "alice" {
		t.Fatalf("unexpected data row: %#v", records[1])
	}
}

func TestRenderReportJSON(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	rows := []auditReportRow{{
		ID:       "a1",
		UserID:   "u1",
		Username: "alice",
		Action:   "session.playback",
	}}

	blob, err := renderReportJSON(reportTypeAudit, "json", map[string]string{"action": "session.playback"}, now, rows)
	if err != nil {
		t.Fatalf("renderReportJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}
	if parsed["report_type"] != reportTypeAudit {
		t.Fatalf("unexpected report_type: %v", parsed["report_type"])
	}
	if parsed["record_count"].(float64) != 1 {
		t.Fatalf("unexpected record_count: %v", parsed["record_count"])
	}
}

func TestRenderAuditPDF(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	rows := []auditReportRow{{
		ID:        "a1",
		UserID:    "u1",
		Username:  "alice",
		Action:    "login",
		Resource:  "user:alice",
		IPAddress: "10.0.0.1",
		Timestamp: now.Format(time.RFC3339),
		Metadata: map[string]interface{}{
			"source": "web",
		},
	}}

	blob, err := renderAuditPDF(rows, nil, now)
	if err != nil {
		t.Fatalf("renderAuditPDF failed: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("expected non-empty PDF")
	}
	if !bytes.HasPrefix(blob, []byte("%PDF")) {
		t.Fatalf("expected PDF signature, got prefix %q", blob[:4])
	}
}

func TestReportFilename(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 34, 56, 0, time.UTC)
	got := reportFilename(reportTypeSessions, "csv", now)
	if got != "sessions-20260723-123456.csv" {
		t.Fatalf("unexpected filename: %s", got)
	}
}
