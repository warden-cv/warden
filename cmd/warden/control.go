package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/warden-cv/warden/internal/server"
)

func runConfig(args []string) int {
	fs := flag.NewFlagSet("warden config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("config", server.DefaultConfigDir(), "Warden configuration directory")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || fs.Arg(0) != "show" {
		fmt.Fprintln(os.Stderr, "usage: warden config show [--config DIR] [--json]")
		return 2
	}
	configDir, err := resolveConfigDir(fs, *dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	value := map[string]string{"project": "warden", "configDir": configDir}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(value)
	} else {
		fmt.Printf("Configuration directory: %s\n", configDir)
	}
	return 0
}

func runSetup(args []string) int {
	fs := flag.NewFlagSet("warden setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("config", server.DefaultConfigDir(), "configuration directory")
	display := fs.String("display-name", "", "deprecated; ignored (display is derived from username)")
	username := fs.String("username", "", "login username")
	email := fs.String("email", "", "login email")
	passwordFile := fs.String("password-file", "", "file containing the password")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *passwordFile == "" || *username == "" {
		fmt.Fprintln(os.Stderr, "usage: warden setup --username NAME --email EMAIL --password-file FILE [--config DIR]")
		return 2
	}
	password, err := os.ReadFile(*passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	if strings.TrimSpace(*email) == "" {
		fmt.Fprintln(os.Stderr, "warden: --email is required")
		return 2
	}
	configDir, err := resolveConfigDir(fs, *dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	displayName := *username
	if strings.TrimSpace(*display) != "" {
		displayName = *display
	}
	if err = os.MkdirAll(configDir, 0700); err == nil {
		err = server.SetupAdministrator(configDir, displayName, *username, *email, strings.TrimRight(string(password), "\r\n"))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	fmt.Println("Warden administrator configured.")
	return 0
}

func runReset(args []string) int {
	fs := flag.NewFlagSet("warden reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	auth := fs.Bool("auth", false, "reset accounts and sessions only")
	all := fs.Bool("all", false, "reset all Warden state; workspace files are preserved")
	dir := fs.String("config", server.DefaultConfigDir(), "Warden configuration directory")
	confirm := fs.String("confirm", "", "non-interactive confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*auth == *all) {
		fmt.Fprintln(os.Stderr, "usage: warden reset (--auth|--all) [--config DIR] [--confirm 'WARDEN AUTH|WARDEN ALL']")
		return 2
	}
	configDir, err := resolveConfigDir(fs, *dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	mode := "AUTH"
	if *all {
		mode = "ALL"
	}
	want := "WARDEN " + mode
	if !wardenConfirm(want, *confirm) {
		fmt.Fprintln(os.Stderr, "warden: confirmation did not match; nothing changed")
		return 1
	}
	if err := resetWarden(configDir, *all); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	fmt.Printf("Warden %s reset complete. A timestamped backup was retained.\n", strings.ToLower(mode))
	return 0
}

// resolveConfigDir applies the canonical instance-resolution precedence shared
// by setup/config/reset: an explicit --config wins, then WARDEN_CONFIG_DIR,
// then the configuration directory recorded by the installed managed service,
// then the normal default. It fails closed rather than silently targeting a
// different instance when the installed unit exists but cannot be used safely.
func resolveConfigDir(fs *flag.FlagSet, explicit string) (string, error) {
	dir := strings.TrimSpace(explicit)
	if !flagProvided(fs, "config") && strings.TrimSpace(os.Getenv("WARDEN_CONFIG_DIR")) == "" {
		installed, installedOK, installedErr := InstalledConfigDir()
		if installedErr != nil {
			return "", installedErr
		}
		if installedOK {
			dir = installed
		}
	}
	return dir, nil
}

func wardenConfirm(want, supplied string) bool {
	if supplied != "" {
		return supplied == want
	}
	fmt.Fprintf(os.Stderr, "Type %q to continue: ", want)
	got, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(got) == want
}

// renameFile is a seam so tests can exercise reset rollback behavior.
var renameFile = os.Rename

func resetWarden(dir string, all bool) error {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if all {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return nil
		}
		if err := renameFile(dir, dir+".reset-"+stamp); err != nil {
			return fmt.Errorf("back up configuration directory: %w", err)
		}
		return os.MkdirAll(dir, 0700)
	}
	backup := filepath.Join(dir, "reset-backups", stamp)
	if err := os.MkdirAll(backup, 0700); err != nil {
		return err
	}
	// The auth reset is a small transaction: accounts and sessions move as one
	// logical unit. If any file fails to move, already-moved files are restored
	// so a partial failure can never leave the half-reset state that would
	// otherwise abort startup on stale sessions.
	moved := []string{}
	for _, name := range []string{"users.json", "sessions.json"} {
		source := filepath.Join(dir, name)
		if _, err := os.Stat(source); os.IsNotExist(err) {
			continue
		}
		if err := renameFile(source, filepath.Join(backup, name)); err != nil {
			for _, movedName := range moved {
				_ = renameFile(filepath.Join(backup, movedName), filepath.Join(dir, movedName))
			}
			return fmt.Errorf("back up %s: %w", name, err)
		}
		moved = append(moved, name)
	}
	return nil
}
