// Command credentials manages an encrypted configuration file, in the shape
// Rails' credentials.yml.enc popularised: one committed ciphertext, one
// gitignored master key.
package main

import (
	"fmt"
	"os"

	"github.com/roonglit/credentials/pkg/credentials"
)

const usage = `Usage: credentials <command>

Commands:
  edit      decrypt, open in $EDITOR, re-encrypt
  show      print the decrypted contents to stdout
  migrate   re-encrypt an old unauthenticated file, without an editor

Environment:
  CREDENTIALS_DIR   directory holding master.key and credentials.yml.enc
                    (default "config")
  VISUAL, EDITOR    editor used by 'edit' (default "vi")
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		fmt.Print(usage)
		os.Exit(2)
	}

	dir := os.Getenv("CREDENTIALS_DIR")
	if dir == "" {
		dir = "config"
	}
	editor := credentials.NewConfigEditor(dir, "credentials.yml.enc", "master.key", "")

	switch args[0] {
	case "edit":
		if err := editor.OpenEditor(); err != nil {
			return err
		}
		fmt.Println("Credentials saved.")
		return nil

	case "show", "read":
		plaintext, err := editor.Show()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(plaintext)
		return err

	case "migrate":
		return editor.Migrate()

	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil

	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}
