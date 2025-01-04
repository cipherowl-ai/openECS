package reload

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileWatcherNotifier implements the Notifier interface using a file watcher.
type FileWatcherNotifier struct {
	filePath    string
	watcher     *fsnotify.Watcher
	reloadDelay time.Duration // Delay between file change events to prevent multiple rapid reloads
}

// NewFileWatcherNotifier creates a new FileWatcherNotifier.
func NewFileWatcherNotifier(filePath string, reloadDelay time.Duration) (*FileWatcherNotifier, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	return &FileWatcherNotifier{
		filePath:    filePath,
		watcher:     watcher,
		reloadDelay: reloadDelay,
	}, nil
}

// WatchForChange monitors the file for changes and triggers the onReload callback when necessary.
// It blocks until the context is canceled or an error occurs.
func (fw *FileWatcherNotifier) WatchForChange(ctx context.Context, onReload func(filePath string) error) error {
	err := fw.watcher.Add(fw.filePath)
	if err != nil {
		return fmt.Errorf("failed to add file to watcher: %v", err)
	}

	debounceTimer := time.NewTimer(0)
	if !debounceTimer.Stop() {
		<-debounceTimer.C
	}

	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return nil // Channel closed, stop the watcher
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				log.Printf("File change detected: %s", fw.filePath)
				debounceTimer.Reset(fw.reloadDelay)
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return nil // Channel closed, stop the watcher
			}
			log.Printf("Error while watching file: %v", err)
			return err

		case <-debounceTimer.C:
			// Call the reload callback
			if err := onReload(fw.filePath); err != nil {
				log.Printf("Error during reload: %v", err)
			}

		case <-ctx.Done():
			log.Println("Stopping file watcher due to context cancellation.")
			return nil
		}
	}
}

// Close halts the file watcher.
func (fw *FileWatcherNotifier) Close() error {
	return fw.watcher.Close()
}
