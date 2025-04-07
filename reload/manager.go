package reload

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cipherowl-ai/openECS/store"
	"golang.org/x/sync/errgroup"
)

// ReloadManager manages the BloomFilterStore and handles notifications for reloading.
type ReloadManager struct {
	store    *store.BloomFilterStore
	notifier Notifier
	eg       *errgroup.Group // Error group to manage concurrent operations.
	ctx      context.Context
	cancel   context.CancelFunc
	logger   *slog.Logger
	mu       sync.RWMutex
	lastLoad time.Time
}

// NewReloadManager creates a new ReloadManager with a specified notification mechanism.
func NewReloadManager(store *store.BloomFilterStore, notifier Notifier) *ReloadManager {
	return &ReloadManager{
		store:    store,
		notifier: notifier,
		logger:   slog.Default(),
	}
}

// NewReloadManager creates a new ReloadManager with a specified notification mechanism.
func NewReloadManagerWithLogger(store *store.BloomFilterStore, notifier Notifier, logger *slog.Logger) *ReloadManager {
	return &ReloadManager{
		store:    store,
		notifier: notifier,
		logger:   logger,
		lastLoad: time.Unix(0, 0),
	}
}

// Start begins listening for notifications to reload the Bloom filter.
func (m *ReloadManager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.eg, m.ctx = errgroup.WithContext(m.ctx)

	// Start the notifier in a managed goroutine.
	m.eg.Go(func() error {
		// Pass a reload callback to the notifier.
		return m.notifier.WatchForChange(m.ctx, func(filePath string) error {
			m.logger.Info("Reloading Bloom filter due to notification.")
			if err := m.store.LoadFromFile(filePath); err != nil {
				m.logger.Error("Error reloading Bloom filter", "error", err)
				return err
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			m.lastLoad = time.Now()
			return nil
		})
	})

	return nil
}

func (m *ReloadManager) LastLoadTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastLoad
}

// Stop halts the notification process and waits for ongoing operations to complete.
func (m *ReloadManager) Stop() error {
	// Cancel the context to stop watching for changes.
	m.cancel()

	// Wait for all goroutines to finish.
	err := m.eg.Wait()
	if errors.Is(err, context.Canceled) {
		// Ignore context.Canceled errors, as they are expected during shutdown.
		err = nil
	}

	// Close the notifier to release resources.
	closeErr := m.notifier.Close()
	if closeErr != nil {
		return closeErr
	}

	return err
}
