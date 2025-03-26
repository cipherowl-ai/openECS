package reload

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type RemoteNotifier struct {
	chain        string
	dataset      string
	localPath    string
	client       RemoteClient
	ticker       *time.Ticker
	lastModified time.Time
	mu           sync.Mutex
	done         chan struct{}
	logger       *slog.Logger
}

func NewRemoteNotifierWithClient(chain, dataset, localPath string, client RemoteClient, checkInterval time.Duration, logger *slog.Logger) *RemoteNotifier {
	return &RemoteNotifier{
		chain:     chain,
		dataset:   dataset,
		localPath: localPath,
		client:    client,
		ticker:    time.NewTicker(checkInterval),
		done:      make(chan struct{}),
		logger:    logger,
	}
}

type EcsDataset struct {
	FileURL      string `json:"fileUrl"`
	LastModified int64  `json:"lastModified"`
	Checksum     string `json:"checksum"`
}

func (e *EcsDataset) LastModifiedTime() time.Time {
	return time.Unix(e.LastModified, 0)
}

func NewRemoteNotifier(chain, dataset, baseURL, clientID, clientSecret, localPath string, checkInterval time.Duration, logger *slog.Logger) *RemoteNotifier {
	return &RemoteNotifier{
		chain:     chain,
		dataset:   dataset,
		client:    NewRemoteClient(baseURL, clientID, clientSecret, logger),
		localPath: localPath,
		ticker:    time.NewTicker(checkInterval),
		done:      make(chan struct{}),
		logger:    logger,
	}
}

func (n *RemoteNotifier) WatchForChange(ctx context.Context, onReload func(file string) error) error {
	// Initial check
	if err := n.checkAndNotify(ctx, onReload); err != nil {
		return fmt.Errorf("initial check failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.done:
			return nil
		case <-n.ticker.C:
			if err := n.checkAndNotify(ctx, onReload); err != nil {
				// Log error but continue watching
				n.logger.Error("Error checking for updates", "error", err)
			}
		}
	}
}

func (n *RemoteNotifier) checkAndNotify(ctx context.Context, onReload func(file string) error) error {
	metadata, err := n.client.FetchMetadata(n.chain, n.dataset)
	if err != nil {
		n.logger.Error("Failed to fetch metadata", "error", err)
		return fmt.Errorf("failed to fetch metadata: %w", err)
	}

	n.mu.Lock()
	needsUpdate := metadata.LastModifiedTime().After(n.lastModified)
	n.mu.Unlock()

	if needsUpdate {
		n.logger.Info("Downloading file", "file", metadata.FileURL)
		if err := n.client.DownloadFile(ctx, metadata.FileURL, n.localPath); err != nil {
			n.logger.Error("Download failed", "error", err)
			return fmt.Errorf("download failed: %w", err)
		}

		if err := onReload(n.localPath); err != nil {
			n.logger.Error("Reload failed", "error", err)
			return fmt.Errorf("reload failed: %w", err)
		}
		n.logger.Info("Reload successful", "file", n.localPath)

		n.mu.Lock()
		n.lastModified = metadata.LastModifiedTime()
		n.mu.Unlock()
	}

	return nil
}

func (n *RemoteNotifier) Close() error {
	n.logger.Info("Stopping remote notifier")
	n.ticker.Stop()
	close(n.done)
	return nil
}
