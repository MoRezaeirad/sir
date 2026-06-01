package kernel

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Ledger is a local append-only hash-chained JSONL evidence store.
// Non-negotiable #7: no raw secrets are stored. Only display paths,
// sensitivity labels, and decision metadata are ledgered.
type Ledger struct {
	path string
}

// OpenLedger opens or creates the ledger at path.
// Only os.IsNotExist can seed a fresh ledger (non-negotiable #3).
func OpenLedger(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("ledger dir: %w", err)
	}
	if _, err := os.Stat(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ledger stat: %w", err)
	}
	return &Ledger{path: path}, nil
}

// Append writes a new entry to the ledger, chaining it to the previous hash.
func (l *Ledger) Append(caseID string, decision Decision) error {
	prev, err := l.lastHash()
	if err != nil {
		return fmt.Errorf("ledger read prev: %w", err)
	}

	entryID := fmt.Sprintf("e-%s-%s", decision.Timestamp, decision.DecisionID[:8])
	entry := LedgerEntry{
		EntryID:  entryID,
		CaseID:   caseID,
		Decision: decision,
		PrevHash: prev,
	}

	// Hash = SHA256(prevHash + JSON(entry without hash field))
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte(prev), body...))
	entry.Hash = hex.EncodeToString(sum[:])

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, string(line)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

// ReadLast returns the most recent ledger entry, or nil if empty.
func (l *Ledger) ReadLast() (*LedgerEntry, error) {
	entries, err := l.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	e := entries[len(entries)-1]
	return &e, nil
}

// ReadAll returns all ledger entries in order.
func (l *Ledger) ReadAll() ([]LedgerEntry, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []LedgerEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e LedgerEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("ledger corrupt: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

func (l *Ledger) lastHash() (string, error) {
	last, err := l.ReadLast()
	if err != nil {
		return "", err
	}
	if last == nil {
		return genesisHash, nil
	}
	return last.Hash, nil
}

// DefaultLedgerPath returns the default v2 ledger path.
func DefaultLedgerPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sir", "v2", "ledger.jsonl")
}
