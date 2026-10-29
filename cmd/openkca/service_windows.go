package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/mailsvb/openkca/internal/config"
)

// serviceName is the Windows service the MSI installs, and the event log
// source it registers.
const serviceName = "OpenKCA"

const (
	adminHint      = "run it in a terminal opened as Administrator"
	restartCommand = "Restart-Service " + serviceName
)

// installedService returns the Windows service that reads the
// configuration file at path, the MSI's OpenKCA, or "".
func installedService(path string) string {
	if !strings.EqualFold(path, config.PackagedPath()) {
		return ""
	}
	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return ""
	}
	s.Close()
	return serviceName
}

func restartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped {
		if st, err = s.Control(svc.Stop); err != nil {
			return err
		}
		for deadline := time.Now().Add(30 * time.Second); st.State != svc.Stopped; {
			if time.Now().After(deadline) {
				return errors.New("the service does not stop")
			}
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return err
			}
		}
	}
	return s.Start()
}

// runAsService runs the server as the Windows service when the service
// control manager started the process, and reports whether it did. The
// service's arguments are those of serve.
func runAsService(args []string) (bool, error) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return false, err
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	return true, svc.Run(serviceName, &service{args: args})
}

type service struct{ args []string }

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// A service has no console: the log goes to the Application event log.
	var h slog.Handler = slog.NewTextHandler(io.Discard, nil)
	if el, err := eventlog.Open(serviceName); err == nil {
		defer el.Close()
		h = newEventHandler(el)
	}
	log := slog.New(h)
	slog.SetDefault(log)
	fail := func(err error) (bool, uint32) {
		log.Error("OpenKCA stopped", "err", err)
		return true, 1
	}

	path, err := configPath(flag.NewFlagSet("serve", flag.ContinueOnError), s.args)
	if err != nil {
		return fail(err)
	}
	cfg, err := prepare(path, log)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("the server ended")
			}
			return fail(err)
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil {
					log.Error("shutdown", "err", err)
				}
				return false, 0
			}
		}
	}
}

// eventHandler writes log records to the event log as text, with the
// level as the event type.
type eventHandler struct {
	el   *eventlog.Log
	mu   *sync.Mutex
	buf  *bytes.Buffer
	text slog.Handler
}

func newEventHandler(el *eventlog.Log) *eventHandler {
	buf := new(bytes.Buffer)
	// the event log has the time
	noTime := func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}
	return &eventHandler{el: el, mu: new(sync.Mutex), buf: buf,
		text: slog.NewTextHandler(buf, &slog.HandlerOptions{ReplaceAttr: noTime})}
}

func (h *eventHandler) Enabled(ctx context.Context, l slog.Level) bool { return h.text.Enabled(ctx, l) }

func (h *eventHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.text.Handle(ctx, r); err != nil {
		return err
	}
	// EventCreate.exe, the source's message file, knows the IDs 1 to 1000
	msg := strings.TrimSpace(h.buf.String())
	switch {
	case r.Level >= slog.LevelError:
		return h.el.Error(1, msg)
	case r.Level >= slog.LevelWarn:
		return h.el.Warning(1, msg)
	}
	return h.el.Info(1, msg)
}

func (h *eventHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.text = h.text.WithAttrs(attrs)
	return &c
}

func (h *eventHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.text = h.text.WithGroup(name)
	return &c
}
