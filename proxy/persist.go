package proxy

// Durable request audit / access log (production persistence + observability).
//
// Records one structured entry per HTTP request: request id, hashed API key,
// method, path, status, latency and response size. Writes are asynchronous and
// non-blocking — if the buffer is full an entry is dropped (and counted) rather
// than stalling the proxied request.
//
// Backend: append-only JSON-lines file (zero dependency). The tutu reference
// defaults to SQLite (modernc.org/sqlite) with a JSONL fallback; this repo keeps
// a single dependency (github.com/google/uuid), so only the JSONL backend is
// compiled in. KIRO_AUDIT_DISABLE turns audit off entirely.
//
// Each entry is flushed immediately (bufio.Flush after every write) so a crash
// loses at most the single in-flight record — no WAL or batched fsync needed.
import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"kiro-go/logger"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// AuditEntry is one persisted request record.
type AuditEntry struct {
	RequestID  string `json:"request_id"`
	TimeUnixMs int64  `json:"ts_ms"`
	APIKeyHash string `json:"api_key_hash,omitempty"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	LatencyMs  int64  `json:"latency_ms"`
	Bytes      int    `json:"bytes"`
}

type auditBackend interface {
	write(AuditEntry) error
	queryRecent(limit int) ([]AuditEntry, error)
	Close() error
}

// ---- JSON-lines backend ----

// jsonlAuditMaxTailBytes bounds how much of the file queryRecent reads when
// looking for the most recent entries. 4 MiB is far more than limit*entrySize
// for any sane limit, while keeping a tail read cheap on a large audit file.
const jsonlAuditMaxTailBytes int64 = 4 << 20

type jsonlAudit struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

func newJSONLAudit(path string) (*jsonlAudit, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &jsonlAudit{f: f, w: bufio.NewWriter(f)}, nil
}

func (j *jsonlAudit) write(e AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.w.Write(b); err != nil {
		return err
	}
	if err := j.w.WriteByte('\n'); err != nil {
		return err
	}
	return j.w.Flush() // flush each entry so a crash loses at most the in-flight write
}

// queryRecent returns the most recent up-to-limit entries by reading the file
// tail. The file is append-only, so the newest entries are at the end.
func (j *jsonlAudit) queryRecent(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	j.mu.Lock()
	path := j.f.Name()
	j.mu.Unlock()

	// Open a separate read handle so the writer's appends keep flowing.
	rf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer rf.Close()

	st, err := rf.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	off := int64(0)
	if size > jsonlAuditMaxTailBytes {
		off = size - jsonlAuditMaxTailBytes
	}
	if _, err := rf.Seek(off, 0); err != nil {
		return nil, err
	}

	// Sliding window of the last `limit` decoded entries.
	var ring []AuditEntry
	sc := bufio.NewScanner(rf)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // skip malformed/partial line (e.g. mid-write tail)
		}
		ring = append(ring, e)
		if len(ring) > limit {
			ring = ring[len(ring)-limit:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ring, nil
}

func (j *jsonlAudit) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.w.Flush(); err != nil {
		_ = j.f.Close()
		return err
	}
	return j.f.Close()
}

// ---- Async store ----

// AuditStore drains entries from a buffered channel to its backend on a single
// writer goroutine. Record never blocks the caller.
type AuditStore struct {
	ch        chan AuditEntry
	backend   auditBackend
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func NewAuditStore(backend auditBackend, bufSize int) *AuditStore {
	if bufSize <= 0 {
		bufSize = 4096
	}
	s := &AuditStore{ch: make(chan AuditEntry, bufSize), backend: backend}
	s.wg.Add(1)
	go s.loop()
	return s
}

func (s *AuditStore) loop() {
	defer s.wg.Done()
	for e := range s.ch {
		if err := s.backend.write(e); err != nil {
			logger.Warnf("[Audit] write failed: %v", err)
		}
	}
}

// Record enqueues an entry without blocking; a full buffer drops the entry.
func (s *AuditStore) Record(e AuditEntry) {
	select {
	case s.ch <- e:
	default:
		metricsAuditDropped()
	}
}

// Close stops the writer, flushing buffered entries, and closes the backend.
func (s *AuditStore) Close() {
	s.closeOnce.Do(func() {
		close(s.ch)
		s.wg.Wait()
		if err := s.backend.Close(); err != nil {
			logger.Warnf("[Audit] close failed: %v", err)
		}
	})
}

// ---- Package-level wiring ----

var globalAudit *AuditStore

// InitAuditStore initializes the process-wide audit store under dir. It is a
// no-op when KIRO_AUDIT_DISABLE is set.
func InitAuditStore(dir string) {
	if strings.TrimSpace(os.Getenv("KIRO_AUDIT_DISABLE")) != "" {
		logger.Infof("[Audit] disabled via KIRO_AUDIT_DISABLE")
		return
	}
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Warnf("[Audit] cannot create dir %s: %v", dir, err)
		return
	}

	// KIRO_AUDIT_BACKEND is accepted for compatibility with kiro-tutu, but only
	// the JSONL backend is compiled in here (zero-dep). Any non-"jsonl" value
	// falls back to JSONL with a one-time info note so operators aren't confused.
	backendName := strings.ToLower(strings.TrimSpace(os.Getenv("KIRO_AUDIT_BACKEND")))
	if backendName != "" && backendName != "jsonl" {
		logger.Infof("[Audit] backend %q requested but only JSONL is compiled in; using JSONL", backendName)
	}
	backendName = "jsonl"

	jb, err := newJSONLAudit(filepath.Join(dir, "kiro-audit.jsonl"))
	if err != nil {
		logger.Errorf("[Audit] disabled: cannot open JSONL backend: %v", err)
		return
	}

	globalAudit = NewAuditStore(jb, 4096)
	logger.Infof("[Audit] enabled (backend=%s, dir=%s)", backendName, dir)
}

// CloseAuditStore flushes and closes the audit store, if any.
func CloseAuditStore() {
	if globalAudit != nil {
		globalAudit.Close()
	}
}

func recordAudit(e AuditEntry) {
	if globalAudit != nil {
		globalAudit.Record(e)
	}
}

func hashAPIKey(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// QueryRecent returns the most recent audit entries when the backend supports it.
func (s *AuditStore) QueryRecent(limit int) ([]AuditEntry, error) {
	return s.backend.queryRecent(limit)
}

// AuditRecent reads recent audit entries from the process-wide store.
func AuditRecent(limit int) ([]AuditEntry, error) {
	if globalAudit == nil {
		return nil, fmt.Errorf("audit store not initialized")
	}
	return globalAudit.QueryRecent(limit)
}
