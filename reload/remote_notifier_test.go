package reload

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Mock RemoteClient for testing
type mockRemoteClient struct {
	metadata    *EcsDataset
	metadataErr error
	downloadErr error
}

func (m *mockRemoteClient) FetchMetadata(chain, dataset string) (*EcsDataset, error) {
	return m.metadata, m.metadataErr
}

func (m *mockRemoteClient) DownloadFile(ctx context.Context, url string, dest string) error {
	return m.downloadErr
}

func TestRemoteNotifier_CheckAndNotify(t *testing.T) {
	tests := []struct {
		name           string
		metadata       *EcsDataset
		metadataErr    error
		downloadErr    error
		expectCallback bool
		expectError    bool
	}{
		{
			name: "successful update",
			metadata: &EcsDataset{
				FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
				LastModified: time.Now(),
				Checksum:     "test-checksum",
			},
			expectCallback: true,
			expectError:    false,
		},
		{
			name:        "metadata fetch error",
			metadataErr: fmt.Errorf("metadata error"),
			expectError: true,
		},
		{
			name: "download error",
			metadata: &EcsDataset{
				FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
				LastModified: time.Now(),
				Checksum:     "test-checksum",
			},
			downloadErr: fmt.Errorf("download error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockRemoteClient{
				metadata:    tt.metadata,
				metadataErr: tt.metadataErr,
				downloadErr: tt.downloadErr,
			}

			notifier := NewRemoteNotifierWithClient(
				"ethereum",
				"test-file",
				"/tmp/test-file",
				client,
				time.Minute,
			)

			callbackCalled := false
			err := notifier.checkAndNotify(context.Background(), func(file string) error {
				callbackCalled = true
				return nil
			})

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectCallback != callbackCalled {
				t.Errorf("callback called = %v, want %v", callbackCalled, tt.expectCallback)
			}
		})
	}
}

func TestRemoteNotifier_WatchForChange(t *testing.T) {
	tests := []struct {
		name           string
		metadata       *EcsDataset
		metadataErr    error
		downloadErr    error
		expectCallback bool
		expectError    bool
	}{
		{
			name: "successful initial check",
			metadata: &EcsDataset{
				FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
				LastModified: time.Now(),
				Checksum:     "test-checksum",
			},
			expectCallback: true,
			expectError:    false,
		},
		{
			name:        "failed initial check",
			metadataErr: fmt.Errorf("initial check failed"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockRemoteClient{
				metadata:    tt.metadata,
				metadataErr: tt.metadataErr,
				downloadErr: tt.downloadErr,
			}

			notifier := NewRemoteNotifierWithClient(
				"ethereum",
				"test-file",
				"/tmp/test-file",
				client,
				100*time.Millisecond,
			)

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			callbackCount := 0
			err := notifier.WatchForChange(ctx, func(file string) error {
				callbackCount++
				return nil
			})

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != context.DeadlineExceeded {
				t.Errorf("expected deadline exceeded error, got: %v", err)
			}
			if tt.expectCallback && callbackCount == 0 {
				t.Error("expected callback to be called at least once")
			}
			if !tt.expectCallback && callbackCount > 0 {
				t.Error("callback was called when it shouldn't have been")
			}
		})
	}
}

func TestRemoteNotifier_Close(t *testing.T) {
	client := &mockRemoteClient{
		metadata: &EcsDataset{
			FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
			LastModified: time.Now(),
			Checksum:     "test-checksum",
		},
	}
	notifier := NewRemoteNotifierWithClient(
		"ethereum",
		"test-file",
		"/tmp/test-file",
		client,
		time.Minute,
	)

	// Start watching in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchDone := make(chan error)
	go func() {
		watchDone <- notifier.WatchForChange(ctx, func(file string) error {
			return nil
		})
	}()

	// Give the goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// Close should stop the watcher
	if err := notifier.Close(); err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}

	// Wait for the watcher to stop
	select {
	case err := <-watchDone:
		if err != nil {
			t.Errorf("unexpected error from watch: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("watcher did not stop after Close")
	}
}

func TestRemoteNotifier_ConcurrentUpdates(t *testing.T) {
	client := &mockRemoteClient{
		metadata: &EcsDataset{
			FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
			LastModified: time.Now(),
			Checksum:     "test-checksum",
		},
	}

	notifier := NewRemoteNotifierWithClient(
		"ethereum",
		"test-file",
		"/tmp/test-file",
		client,
		100*time.Millisecond,
	)

	// Run multiple concurrent checks
	var errs []error
	for i := 0; i < 10; i++ {
		err := notifier.checkAndNotify(context.Background(), func(file string) error {
			return nil
		})
		errs = append(errs, err)
	}

	// Check that all operations completed without errors
	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent check %d failed: %v", i, err)
		}
	}
}

func TestRemoteNotifier_CallbackError(t *testing.T) {
	client := &mockRemoteClient{
		metadata: &EcsDataset{
			FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
			LastModified: time.Now(),
			Checksum:     "test-checksum",
		},
	}

	notifier := NewRemoteNotifierWithClient(
		"ethereum",
		"test-file",
		"/tmp/test-file",
		client,
		time.Minute,
	)

	expectedErr := fmt.Errorf("callback error")
	err := notifier.checkAndNotify(context.Background(), func(file string) error {
		return expectedErr
	})

	if err == nil {
		t.Error("expected error from callback but got none")
	}
	if err.Error() != "reload failed: callback error" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRemoteNotifier_ContextCancellation(t *testing.T) {
	client := &mockRemoteClient{
		metadata: &EcsDataset{
			FileURL:      "https://test-bucket.s3.amazonaws.com/test-key",
			LastModified: time.Now(),
			Checksum:     "test-checksum",
		},
	}

	notifier := NewRemoteNotifierWithClient(
		"ethereum",
		"test-file",
		"/tmp/test-file",
		client,
		time.Minute,
	)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context immediately
	cancel()

	err := notifier.WatchForChange(ctx, func(file string) error {
		return nil
	})

	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}
