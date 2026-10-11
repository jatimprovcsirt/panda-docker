package service

import (
	"encoding/json"
	"io"
	"sync"
)

// WriterSink writes audit records as newline-delimited JSON to a writer.
//
// JSON rather than a formatted string, because the audit trail is read by
// something — a log pipeline, a SIEM, an auditor's script. A human-readable
// line would have to be parsed back into fields at exactly the moment someone
// needs it most.
type WriterSink struct {
	mu  sync.Mutex
	out io.Writer
}

func NewWriterSink(out io.Writer) *WriterSink {
	return &WriterSink{out: out}
}

// auditLine is the serialised shape. Field names are stable: a downstream
// query written against them must keep working across releases.
type auditLine struct {
	Event     string `json:"event"`
	Timestamp string `json:"ts,omitempty"`
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
	KID       string `json:"kid,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	ClientCN  string `json:"client_cn,omitempty"`
	APIKeyID  string `json:"api_key_id,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Record implements AuditSink.
//
// Note what is not here: no plaintext, no ciphertext, no envelope. The struct
// has nowhere to put them, which is the point — a finding or an audit record
// that carries a matched value has leaked it into whatever reads the stream.
func (s *WriterSink) Record(r AuditRecord) {
	line := auditLine{
		Event:     "panda_audit",
		Operation: r.Operation,
		Outcome:   r.Outcome,
		KID:       r.KID,
		ErrorCode: string(r.ErrorCode),
		ClientCN:  r.Actor.ClientCN,
		APIKeyID:  r.Actor.APIKeyID,
		SourceIP:  r.Actor.SourceIP,
		RequestID: r.Actor.RequestID,
	}

	encoded, err := json.Marshal(line)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, _ = s.out.Write(encoded)
	_, _ = s.out.Write([]byte("\n"))
}
