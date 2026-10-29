package main

import (
	"os"
	"os/exec"

	"github.com/mailsvb/openkca/internal/config"
)

const (
	adminHint      = "run it with sudo"
	restartCommand = "sudo systemctl restart openkca"
)

// installedService returns the systemd service that reads the
// configuration file at path, the rpm's openkca, or "".
func installedService(path string) string {
	if path != config.PackagedPath() {
		return ""
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return ""
	}
	for _, unit := range []string{"/usr/lib/systemd/system/openkca.service", "/etc/systemd/system/openkca.service"} {
		if _, err := os.Stat(unit); err == nil {
			return "openkca"
		}
	}
	return ""
}

func restartService(name string) error {
	cmd := exec.Command("systemctl", "restart", name)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}
