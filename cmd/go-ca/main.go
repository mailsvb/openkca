// Command go-ca serves a web UI for XCA databases.
//
//	go-ca set-password --data-dir DIR   set the server password
//	go-ca [serve] --data-dir DIR [--listen :8443] [--tls-cert F --tls-key F]
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/mailsvb/go-ca/internal/auth"
	"github.com/mailsvb/go-ca/internal/i18n"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/web"
)

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "set-password":
		err = setPassword(args)
	default:
		err = fmt.Errorf("unknown command %q (use serve or set-password)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "go-ca:", err)
		os.Exit(1)
	}
}

func readPassword(prompt string) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return pw, err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func setPassword(args []string) error {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data folder holding the .xdb files (required)")
	fs.Parse(args)
	if *dataDir == "" {
		return errors.New("--data-dir is required")
	}
	pw, err := readPassword("New server password: ")
	if err != nil {
		return err
	}
	if len(pw) < 8 {
		return errors.New("the server password must have at least 8 characters")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again, err := readPassword("Repeat: ")
		if err != nil {
			return err
		}
		if string(again) != string(pw) {
			return errors.New("the passwords do not match")
		}
	}
	if err := auth.SavePassword(*dataDir, pw); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "server password saved to", auth.PasswordPath(*dataDir))
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data folder holding the .xdb files (required)")
	listen := fs.String("listen", ":8443", "address to listen on")
	certFile := fs.String("tls-cert", "", "TLS certificate (PEM); default: self-issued certificate in <data-dir>/.go-ca/")
	keyFile := fs.String("tls-key", "", "TLS private key (PEM) for --tls-cert")
	idle := fs.Duration("idle-timeout", 30*time.Minute, "idle timeout of server and database sessions")
	maxUpload := fs.Int64("max-upload", 256, "largest upload accepted (database file or items to import), in MB")
	fs.Parse(args)
	if *dataDir == "" {
		return errors.New("--data-dir is required")
	}
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("--tls-cert and --tls-key go together")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	st, err := store.New(*dataDir)
	if err != nil {
		return err
	}
	hash, err := auth.LoadPassword(st.Dir)
	if err != nil {
		return err
	}
	certs, err := auth.NewCertManager(st.Dir, *certFile, *keyFile)
	if err != nil {
		return err
	}
	cat, err := i18n.Load()
	if err != nil {
		return err
	}
	srv, err := web.New(web.Config{Store: st, PasswordHash: hash, Catalog: cat, IdleTimeout: *idle,
		MaxUpload: *maxUpload << 20, Logger: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ran := make(chan struct{})
	go func() { srv.Run(ctx); close(ran) }()
	go certs.Watch(ctx.Done())

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	leaf := certs.Leaf()
	log.Info("go-ca listening", "addr", *listen, "data", st.Dir, "cert", leaf.Subject.CommonName, "expires", leaf.NotAfter.Format(time.DateOnly))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = hs.Shutdown(shutdownCtx)
	<-ran // databases closed, locks released
	return err
}
