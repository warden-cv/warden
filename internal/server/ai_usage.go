package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type aiUsageCounter struct {
	Requests         uint64    `json:"requests"`
	InputTokens      uint64    `json:"input_tokens"`
	OutputTokens     uint64    `json:"output_tokens"`
	EstimatedCostUSD float64   `json:"estimated_cost_usd"`
	UpdatedAt        time.Time `json:"updated_at,omitempty"`
}

type aiAccountUsage struct {
	Providers map[string]aiUsageCounter `json:"providers"`
}

type aiUsageFile struct {
	Version  int                       `json:"version"`
	Accounts map[string]aiAccountUsage `json:"accounts"`
}

type aiUsageStore struct {
	mu   sync.RWMutex
	dir  string
	data aiUsageFile
}

type aiUsageSummary struct {
	Provider         string  `json:"provider"`
	Requests         uint64  `json:"requests"`
	InputTokens      uint64  `json:"inputTokens"`
	OutputTokens     uint64  `json:"outputTokens"`
	EstimatedCostUSD float64 `json:"estimatedCostUsd"`
}

func loadAIUsageStore(dir string) (*aiUsageStore, error) {
	path := filepath.Join(dir, "ai-usage.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeJSONAtomic(path, aiUsageFile{Version: configSchemaVersion, Accounts: map[string]aiAccountUsage{}}, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	s := &aiUsageStore{dir: dir}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *aiUsageStore) reload() error {
	var next aiUsageFile
	if err := readJSONStrict(filepath.Join(s.dir, "ai-usage.json"), &next); err != nil {
		return fmt.Errorf("ai-usage.json: %w", err)
	}
	if next.Version != configSchemaVersion {
		return fmt.Errorf("ai-usage.json: unsupported schema version %d", next.Version)
	}
	if next.Accounts == nil {
		next.Accounts = map[string]aiAccountUsage{}
	}
	for id, usage := range next.Accounts {
		if id == "" {
			return errors.New("ai-usage.json: empty account id")
		}
		if usage.Providers == nil {
			usage.Providers = map[string]aiUsageCounter{}
			next.Accounts[id] = usage
		}
	}
	s.mu.Lock()
	s.data = next
	s.mu.Unlock()
	return nil
}

func (s *aiUsageStore) record(accountID, provider string, inputTokens, outputTokens uint64, estimatedCostUSD float64) error {
	if accountID == "" || provider == "" {
		return errors.New("account and provider are required")
	}
	if estimatedCostUSD < 0 {
		return errors.New("estimated cost cannot be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := aiUsageFile{Version: configSchemaVersion, Accounts: map[string]aiAccountUsage{}}
	for id, usage := range s.data.Accounts {
		copied := aiAccountUsage{Providers: map[string]aiUsageCounter{}}
		for p, c := range usage.Providers {
			copied.Providers[p] = c
		}
		next.Accounts[id] = copied
	}
	usage := next.Accounts[accountID]
	if usage.Providers == nil {
		usage.Providers = map[string]aiUsageCounter{}
	}
	c := usage.Providers[provider]
	c.Requests++
	c.InputTokens += inputTokens
	c.OutputTokens += outputTokens
	c.EstimatedCostUSD += estimatedCostUSD
	c.UpdatedAt = time.Now().UTC()
	usage.Providers[provider] = c
	next.Accounts[accountID] = usage
	if err := writeJSONAtomic(filepath.Join(s.dir, "ai-usage.json"), next, false); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *aiUsageStore) reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := aiUsageFile{Version: configSchemaVersion, Accounts: map[string]aiAccountUsage{}}
	if err := writeJSONAtomic(filepath.Join(s.dir, "ai-usage.json"), next, false); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *aiUsageStore) allSummaries() map[string][]aiUsageSummary {
	s.mu.RLock()
	ids := make([]string, 0, len(s.data.Accounts))
	for id := range s.data.Accounts {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	sort.Strings(ids)
	out := make(map[string][]aiUsageSummary, len(ids))
	for _, id := range ids {
		out[id] = s.summary(id)
	}
	return out
}

func (s *aiUsageStore) summary(accountID string) []aiUsageSummary {
	s.mu.RLock()
	usage := s.data.Accounts[accountID]
	s.mu.RUnlock()
	ids := make([]string, 0, len(usage.Providers))
	for id := range usage.Providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]aiUsageSummary, 0, len(ids))
	for _, id := range ids {
		c := usage.Providers[id]
		out = append(out, aiUsageSummary{Provider: id, Requests: c.Requests, InputTokens: c.InputTokens, OutputTokens: c.OutputTokens, EstimatedCostUSD: c.EstimatedCostUSD})
	}
	return out
}
