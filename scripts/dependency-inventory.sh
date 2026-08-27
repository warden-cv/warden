#!/bin/sh
set -eu
go list -m -f '{{if not .Main}}{{.Path}} {{.Version}}{{end}}' all | sed '/^$/d' | sort
