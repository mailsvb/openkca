//go:build !windows

package main

// runAsService reports false: only Windows runs OpenKCA as a service of
// its own making; systemd runs "openkca serve".
func runAsService([]string) (bool, error) { return false, nil }
