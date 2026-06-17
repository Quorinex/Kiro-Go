package proxy

import (
	"sync"
	"time"
)

const defaultMaxLogs = 1000

// RequestLog represents a single API request log entry.
type RequestLog struct {
	Timestamp    int64   `json:"timestamp"`
	Path         string  `json:"path"`
	Model        string  `json:"model"`
	Status       int     `json:"status"`
	InputTokens  int     `json:"inputTokens"`
	OutputTokens int     `json:"outputTokens"`
	CacheRead    int     `json:"cacheRead"`
	CacheWrite   int     `json:"cacheWrite"`
	Credits      float64 `json:"credits"`
	LatencyMs    int64   `json:"latencyMs"`
	ApiKeyID     string  `json:"apiKeyId"`
	ApiKeyName   string  `json:"apiKeyName"`
	Error        string  `json:"error,omitempty"`
}

// LogStore stores recent request logs in memory with a fixed capacity.
type LogStore struct {
	mu      sync.RWMutex
	logs    []RequestLog
	maxLogs int
}

// NewLogStore creates a log store with the given capacity.
func NewLogStore(maxLogs int) *LogStore {
	if maxLogs <= 0 {
		maxLogs = defaultMaxLogs
	}
	return &LogStore{
		logs:    make([]RequestLog, 0, maxLogs),
		maxLogs: maxLogs,
	}
}

// Add appends a log entry, evicting the oldest if at capacity.
func (s *LogStore) Add(entry RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.Timestamp == 0 {
		entry.Timestamp = time.Now().UnixMilli()
	}

	s.logs = append(s.logs, entry)
	if len(s.logs) > s.maxLogs {
		// Remove oldest entries
		excess := len(s.logs) - s.maxLogs
		s.logs = s.logs[excess:]
	}
}

// GetLast returns the most recent n entries (newest last).
func (s *LogStore) GetLast(n int) []RequestLog {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n <= 0 || len(s.logs) == 0 {
		return nil
	}
	start := len(s.logs) - n
	if start < 0 {
		start = 0
	}
	result := make([]RequestLog, len(s.logs)-start)
	copy(result, s.logs[start:])
	return result
}

// GetFiltered returns recent entries filtered by apiKeyID or apiKeyName.
func (s *LogStore) GetFiltered(filter string, limit int) []RequestLog {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if filter == "" {
		return s.GetLastUnlocked(limit)
	}

	var result []RequestLog
	// Iterate from newest to oldest
	for i := len(s.logs) - 1; i >= 0; i-- {
		entry := s.logs[i]
		if entry.ApiKeyID == filter || entry.ApiKeyName == filter {
			result = append(result, entry)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	// Reverse to get chronological order
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// GetLastUnlocked returns recent entries without lock (caller must hold RLock).
func (s *LogStore) GetLastUnlocked(n int) []RequestLog {
	if n <= 0 || len(s.logs) == 0 {
		return nil
	}
	start := len(s.logs) - n
	if start < 0 {
		start = 0
	}
	result := make([]RequestLog, len(s.logs)-start)
	copy(result, s.logs[start:])
	return result
}

// Stats returns aggregate statistics.
type LogStats struct {
	Total       int   `json:"total"`
	Success     int   `json:"success"`
	Failed      int   `json:"failed"`
	TotalInput  int64 `json:"totalInput"`
	TotalOutput int64 `json:"totalOutput"`
	TotalCache  int64 `json:"totalCacheRead"`
}

func (s *LogStore) Stats() LogStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats LogStats
	stats.Total = len(s.logs)
	for _, l := range s.logs {
		if l.Status == 200 {
			stats.Success++
		} else {
			stats.Failed++
		}
		stats.TotalInput += int64(l.InputTokens)
		stats.TotalOutput += int64(l.OutputTokens)
		stats.TotalCache += int64(l.CacheRead)
	}
	return stats
}

// Clear removes all logs.
func (s *LogStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = s.logs[:0]
}
