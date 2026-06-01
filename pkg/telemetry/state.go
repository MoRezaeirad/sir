package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/somoore/sir/pkg/session"
)

const healthSchemaVersion = 1

// Health captures coarse-grained telemetry exporter health for operability
// surfaces such as `sir status` and `sir doctor`.
type Health struct {
	SchemaVersion      uint32    `json:"schema_version"`
	EndpointConfigured bool      `json:"endpoint_configured"`
	QueueSize          int       `json:"queue_size,omitempty"`
	WorkerCount        int       `json:"worker_count,omitempty"`
	QueuedCount        uint64    `json:"queued_count,omitempty"`
	DroppedCount       uint64    `json:"dropped_count,omitempty"`
	LastEmitAt         time.Time `json:"last_emit_at,omitempty"`
	LastDropAt         time.Time `json:"last_drop_at,omitempty"`
}

// HealthPath returns the durable telemetry health file path for a project.
func HealthPath(projectRoot string) string {
	return filepath.Join(session.DurableStateDir(projectRoot), "telemetry.json")
}

func loadHealth(projectRoot string) (*Health, error) {
	data, err := os.ReadFile(HealthPath(projectRoot))
	if err != nil {
		return nil, err
	}
	var health Health
	if err := json.Unmarshal(data, &health); err != nil {
		return nil, err
	}
	if health.SchemaVersion == 0 {
		health.SchemaVersion = healthSchemaVersion
	}
	return &health, nil
}

// LoadHealth loads the durable telemetry health snapshot for a project.
func LoadHealth(projectRoot string) (*Health, error) {
	health, err := loadHealth(projectRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return health, nil
}


func recordHealth(projectRoot string, endpointConfigured bool, queueSize, workerCount int, queued, dropped uint64, now time.Time) error {
	if projectRoot == "" {
		return nil
	}
	return withHealthLock(projectRoot, func() error {
		health, err := loadHealth(projectRoot)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			health = &Health{SchemaVersion: healthSchemaVersion}
		}
		health.SchemaVersion = healthSchemaVersion
		health.EndpointConfigured = endpointConfigured
		health.QueueSize = queueSize
		health.WorkerCount = workerCount
		health.QueuedCount += queued
		health.DroppedCount += dropped
		if queued > 0 {
			health.LastEmitAt = now
		}
		if dropped > 0 {
			health.LastDropAt = now
		}
		data, err := json.MarshalIndent(health, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(HealthPath(projectRoot), data, 0o600)
	})
}
