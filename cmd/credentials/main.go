package main

import (
	"fmt"
	"log"
	"os"

	"github.com/roonglit/credentials/pkg/credentials"
)

func main() {
	// Set up file paths and editor
	configDir := "config"
	credentialsFile := "credentials.yml.enc"
	masterKeyFile := "master.key"
	editor := "vim" // Set your preferred editor here

	// Check command-line arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: credentials <edit|read>")
		os.Exit(1)
	}

	// credentials.ICommand = *&credentials.CommandRunner{}
	switch os.Args[1] {
	case "edit":
		executor := &credentials.CommandExecutor{}
		fileManager := &credentials.FileManager{}
		editor := credentials.NewConfigEditor(configDir, credentialsFile, masterKeyFile, editor, executor, fileManager)
		if err := editor.Open(); err != nil {
			log.Fatal("Failed to edit credentials:", err)
		}
		fmt.Println("Credentials updated successfully.")
	default:
		fmt.Println("Unknown command. Use 'edit' or 'read'.")
		os.Exit(1)
	}
}
