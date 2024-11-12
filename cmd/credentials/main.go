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

	switch os.Args[1] {
	case "edit":
		editor := credentials.NewConfigEditor(configDir, credentialsFile, masterKeyFile, editor)
		if err := editor.OpenEditor(); err != nil {
			log.Fatal("Failed to edit credentials:", err)
		}
		fmt.Println("Credentials updated successfully.")
	default:
		fmt.Println("Unknown command. Use 'edit' or 'read'.")
		os.Exit(1)
	}
}
