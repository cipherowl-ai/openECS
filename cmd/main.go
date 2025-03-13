package main

import (
	"fmt"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
)

func main() {
	// Check for the correct usage
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <file-to-watch>")
		return
	}

	// Get the file to watch from the command-line arguments
	filePath := os.Args[1]

	// Create a new watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Error creating watcher: %v", err)
	}
	defer watcher.Close()

	// Add the file to the watcher
	err = watcher.Add(filePath)
	if err != nil {
		log.Fatalf("Error adding file to watcher: %v", err)
	}

	fmt.Printf("Watching file: %s\n", filePath)

	// Start a goroutine to process events
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				fmt.Printf("Event: %s, File: %s\n", event.Op, event.Name)

				// Check specific events
				if event.Op&fsnotify.Write == fsnotify.Write {
					fmt.Println("File was written to")
				}
				if event.Op&fsnotify.Remove == fsnotify.Remove {
					fmt.Println("File was removed")
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					fmt.Println("File was created")
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Error: %v\n", err)
			}
		}
	}()

	// Block forever
	select {}
}
