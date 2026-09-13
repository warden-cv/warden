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
	value := map[string]string{"project": "warden", "configDir": *dir}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(value)
	} else {
		fmt.Printf("Configuration directory: %s\n", *dir)
	}
	return 0
}

func runSetup(args []string) int {
	fs := flag.NewFlagSet("warden setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("config", server.DefaultConfigDir(), "configuration directory")
	display := fs.String("display-name", "Administrator", "display name")
	username := fs.String("username", "admin", "login username")
	passwordFile := fs.String("password-file", "", "file containing the password")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *passwordFile == "" {
		fmt.Fprintln(os.Stderr, "usage: warden setup --password-file FILE [--username NAME] [--display-name NAME] [--config DIR]")
		return 2
	}
	password, err := os.ReadFile(*passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	if err = os.MkdirAll(*dir, 0700); err == nil {
		err = server.SetupAdministrator(*dir, *display, *username, strings.TrimRight(string(password), "\r\n"))
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
	mode := "AUTH"
	if *all {
		mode = "ALL"
	}
	want := "WARDEN " + mode
	if !wardenConfirm(want, *confirm) {
		fmt.Fprintln(os.Stderr, "warden: confirmation did not match; nothing changed")
		return 1
	}
	if err := resetWarden(*dir, *all); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 1
	}
	fmt.Printf("Warden %s reset complete. A timestamped backup was retained.\n", strings.ToLower(mode))
	return 0
}

func wardenConfirm(want, supplied string) bool {
	if supplied != "" {
		return supplied == want
	}
	fmt.Fprintf(os.Stderr, "Type %q to continue: ", want)
	got, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(got) == want
}

func resetWarden(dir string, all bool) error {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if all {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return nil
		}
		if err := os.Rename(dir, dir+".reset-"+stamp); err != nil {
			return fmt.Errorf("back up configuration directory: %w", err)
		}
		return os.MkdirAll(dir, 0700)
	}
	backup := filepath.Join(dir, "reset-backups", stamp)
	if err := os.MkdirAll(backup, 0700); err != nil {
		return err
	}
	for _, name := range []string{"users.json", "roles.json"} {
		source := filepath.Join(dir, name)
		if _, err := os.Stat(source); os.IsNotExist(err) {
			continue
		}
		if err := os.Rename(source, filepath.Join(backup, name)); err != nil {
			return err
		}
	}
	return nil
}
