package reload

import (
	"context"
	"errors"
	"github.com/cipherowl-ai/addressdb/store"
	"golang.org/x/sync/errgroup"
	"log"
)

// ReloadManager manages the BloomFilterStore and handles notifications for reloading.
type ReloadManager struct {
	store    *store.BloomFilterStore
	notifier Notifier
	eg       *errgroup.Group // Error group to manage concurrent operations.
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewReloadManager creates a new ReloadManager with a specified notification mechanism.
func NewReloadManager(store *store.BloomFilterStore, notifier Notifier) *ReloadManager {
	return &ReloadManager{
		store:    store,
		notifier: notifier,
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
			log.Println("Reloading Bloom filter due to notification.")
			return m.store.LoadFromFile(filePath) // Reload the Bloom filter.
		})
	})

	return nil
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
