package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Default Warden host and port used by the shared project configuration
// pattern. Warden's default listener is 127.0.0.1:7332; both remain
// configurable. An existing config.json stays the durable source of truth once
// it exists.
const (
	defaultHost = "127.0.0.1"
	defaultPort = "7332"
)

// flagProvided reports whether name was explicitly supplied on the command
// line. Standard flag strings cannot otherwise distinguish `--port ""` from an
// absent flag, and the contract requires empty CLI values to fail.
func flagProvided(fs *flag.FlagSet, name string) bool {
	provided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

// validatePort reports whether p is a valid TCP port: an integer from 1
// through 65535. It never silently falls back to a default.
func validatePort(p string) error {
	n, err := strconv.Atoi(strings.TrimSpace(p))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be an integer from 1 through 65535; got %q", p)
	}
	return nil
}

// resolveHostPort computes the effective bind host and port. Precedence per
// field is CLI flag > environment variable > default. Values are trimmed once
// and the canonical trimmed form is returned, so surrounding whitespace cannot
// leak into the listener string. A port that is present but empty, malformed,
// zero, negative or greater than 65535 is an error; an empty host value is
// rejected rather than silently meaning "all interfaces".
func resolveHostPort(hostFlag, portFlag string, hostSet, portSet bool) (host, port string, err error) {
	host = defaultHost
	if hostSet {
		host = strings.TrimSpace(hostFlag)
		if host == "" {
			return "", "", errors.New("--host is set but empty")
		}
	} else if v, ok := os.LookupEnv("WARDEN_HOST"); ok {
		host = strings.TrimSpace(v)
		if host == "" {
			return "", "", errors.New("WARDEN_HOST is set but empty")
		}
	}
	port = defaultPort
	if portSet {
		if err := validatePort(portFlag); err != nil {
			return "", "", fmt.Errorf("--port: %w", err)
		}
		port = strings.TrimSpace(portFlag)
	} else if v, ok := os.LookupEnv("WARDEN_PORT"); ok {
		if err := validatePort(v); err != nil {
			return "", "", fmt.Errorf("WARDEN_PORT: %w", err)
		}
		port = strings.TrimSpace(v)
	}
	return host, port, nil
}

// resolveListener computes the effective HTTP listen address from the CLI
// flags and environment. The legacy single-address form (--listen flag or
// WARDEN_LISTEN environment) is preserved for compatibility and cannot be
// combined with --host/--port. IPv6 hosts are bracketed via net.JoinHostPort.
func resolveListener(hostFlag, portFlag, listenFlag string, hostSet, portSet, listenSet bool) (string, error) {
	legacy := ""
	if listenSet {
		legacy = listenFlag
		if strings.TrimSpace(legacy) == "" {
			return "", errors.New("--listen is set but empty")
		}
	} else if v, ok := os.LookupEnv("WARDEN_LISTEN"); ok {
		if strings.TrimSpace(v) == "" {
			return "", errors.New("WARDEN_LISTEN is set but empty")
		}
		legacy = v
	}
	if legacy != "" {
		if hostSet || portSet {
			return "", errors.New("--host/--port cannot be combined with the legacy listen address")
		}
		return legacy, nil
	}
	host, port, err := resolveHostPort(hostFlag, portFlag, hostSet, portSet)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}
