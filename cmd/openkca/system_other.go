//go:build !linux && !windows

package main

import "errors"

const (
	adminHint      = "run it with sudo"
	restartCommand = ""
)

// installedService returns "": OpenKCA is packaged as a service for Linux
// and Windows only.
func installedService(string) string { return "" }

func restartService(string) error { return errors.New("not supported") }
