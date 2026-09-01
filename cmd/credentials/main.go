// Command credentials manages encrypted configuration, in the shape Rails
// popularised: committed ciphertext, a key that is never committed.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/roonglit/credentials/pkg/credentials"
)

const usage = `Usage: credentials <command> [-e ENVIRONMENT]

Commands:
  edit      decrypt, open in $EDITOR, re-encrypt
  show      print the decrypted contents to stdout
  migrate   re-encrypt an old unauthenticated file, without an editor

Flags:
  -e, --environment ENV   operate on config/credentials/ENV.yml.enc with its own
                          key, instead of the shared config/credentials.yml.enc

Environment:
  CREDENTIALS_DIR          directory holding the files (default "config")
  CREDENTIALS_KEY          hex key, used instead of any key file
  CREDENTIALS_ALLOW_LEGACY set to 0 to refuse pre-v2 files rather than warn
  VISUAL, EDITOR           editor used by 'edit' (default "vi")

Why environments get their own key: with a single shared key, anyone who can
boot the app in development can decrypt production. Separate files mean separate
keys, so a leaked development key leaks only development.
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
	command, rest := args[0], args[1:]

	fs := flag.NewFlagSet("credentials", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var environment string
	fs.StringVar(&environment, "e", "", "environment")
	fs.StringVar(&environment, "environment", "", "environment")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	dir := os.Getenv("CREDENTIALS_DIR")
	if dir == "" {
		dir = "config"
	}

	editor := credentials.NewConfigEditor(dir, "credentials.yml.enc", "master.key", "")
	if environment != "" {
		editor = credentials.NewEnvironmentEditor(dir, environment, "")
	}

	switch command {
	case "edit":
		if err := editor.OpenEditor(); err != nil {
			return err
		}
		fmt.Println("Credentials saved:", editor.CredentialsFile)
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
		return fmt.Errorf("unknown command %q", command)
	}
}
