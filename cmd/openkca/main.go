// Command go-ca serves a web UI for XCA databases. Its settings and the
// databases it keeps open come from a YAML configuration file (package
// config).
//
//	go-ca [serve] [--config FILE]   run the server
//	go-ca set-password              print a server password hash for general.password_hash
//	go-ca version                   print the version
//
// The configuration file defaults to config.yaml next to the executable.
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

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/background"
	"github.com/mailsvb/openkca/internal/config"
	"github.com/mailsvb/openkca/internal/i18n"
	"github.com/mailsvb/openkca/internal/pubserve"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/web"
)

// version is set at build time: -ldflags "-X main.version=0.10.0".
var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && (!strings.HasPrefix(args[0], "-") || args[0] == "--version" || args[0] == "-version") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "set-password":
		err = setPassword(args)
	case "version", "--version", "-version":
		fmt.Println("go-ca", version)
	default:
		err = fmt.Errorf("unknown command %q (use serve, set-password or version)", cmd)
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

// setPassword reads a new server password and prints its hash as the
// line to put into the general section of the configuration file.
func setPassword(args []string) error {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() > 0 {
		return errors.New("set-password takes no arguments")
	}
	pw, err := readPassword("New server password: ")
	if err != nil {
		return err
	}
	defer clear(pw)
	if len(pw) < 8 {
		return errors.New("the server password must have at least 8 characters")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again, err := readPassword("Repeat: ")
		if err != nil {
			return err
		}
		defer clear(again)
		if string(again) != string(pw) {
			return errors.New("the passwords do not match")
		}
		fmt.Fprintln(os.Stderr, "Put this line into the general section of the configuration file:")
	}
	fmt.Printf("  password_hash: %q\n", auth.HashPassword(pw))
	return nil
}

// configPath parses the --config flag, the only command line option.
func configPath(fs *flag.FlagSet, args []string) (string, error) {
	file := fs.String("config", "", "configuration file (default: "+config.FileName+" next to the executable)")
	fs.Parse(args)
	if fs.NArg() > 0 {
		return "", fmt.Errorf("unexpected argument %q: all settings are in the configuration file", fs.Arg(0))
	}
	if *file != "" {
		return *file, nil
	}
	return config.DefaultPath()
}

func serve(args []string) error {
	path, err := configPath(flag.NewFlagSet("serve", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	g := cfg.General
	if w := cfg.CheckPermissions(); w != "" {
		log.Warn(w)
	}
	if g.PasswordHash == "" {
		msg := "general.password_hash is missing; run \"go-ca set-password\" and put its output into " + cfg.File
		if legacy := auth.LegacyPasswordPath(g.DataDir); fileExists(legacy) {
			msg += " (or copy the hash from " + legacy + ")"
		}
		return errors.New(msg)
	}
	if !auth.ValidHash(g.PasswordHash) {
		return errors.New("general.password_hash is not a hash made by \"go-ca set-password\"")
	}

	st, err := store.New(g.DataDir)
	if err != nil {
		return err
	}
	st.BaseURLs = cfg.CRL.BaseURLs
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := make([]store.Configured, len(cfg.Databases))
	for i, d := range cfg.Databases {
		conf[i] = store.Configured{Label: d.Name, Path: d.Path, Background: d.Background()}
	}
	names, err := st.Configure(ctx, conf)
	if err != nil {
		return fmt.Errorf("%s: %w", cfg.File, err)
	}
	passwords := map[string][]byte{}
	for i, d := range cfg.Databases {
		if d.Background() {
			passwords[names[i]] = []byte(d.Password)
		}
	}
	bg, err := background.Open(ctx, st, names, passwords)
	for _, pw := range passwords {
		clear(pw)
	}
	if err != nil {
		return err
	}
	defer bg.Close()

	certs, err := auth.NewCertManager(st.Dir, g.TLSCert, g.TLSKey)
	if err != nil {
		return err
	}
	cat, err := i18n.Load()
	if err != nil {
		return err
	}
	monitor := &pubserve.Monitor{Dir: st.Dir, Log: log}
	srv, err := web.New(web.Config{Store: st, PasswordHash: g.PasswordHash, Catalog: cat, IdleTimeout: g.IdleTimeout,
		MaxUpload: g.MaxUploadMB << 20, Logger: log, CRLAlerts: monitor.Alerts})
	if err != nil {
		return err
	}
	ran := make(chan struct{})
	go func() { srv.Run(ctx); close(ran) }()
	go certs.Watch(ctx.Done())
	go monitor.Run(ctx, time.Hour)
	bgDone := make(chan struct{})
	go func() { bg.Run(ctx); close(bgDone) }()

	// The plain HTTP server for CRLs and CA certificates.
	var pub *http.Server
	errc := make(chan error, 2)
	if addr := cfg.CRL.ListenAddr(); addr != "" {
		pub = pubserve.NewServer(addr, &pubserve.Handler{Dir: st.Dir, Log: log})
		go func() {
			if err := pub.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("CRL server: %w", err)
			}
		}()
		log.Info("publishing CRLs and CA certificates over HTTP", "addr", addr, "base_urls", strings.Join(cfg.CRL.BaseURLs, " "))
	}

	hs := &http.Server{
		Addr:              g.Listen,
		Handler:           srv,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	leaf := certs.Leaf()
	log.Info("go-ca listening", "version", version, "config", cfg.File, "addr", g.Listen, "data", st.Dir,
		"databases", len(names), "background", len(bg.Databases()),
		"cert", leaf.Subject.CommonName, "expires", leaf.NotAfter.Format(time.DateOnly))
	select {
	case err := <-errc:
		stop()
		if pub != nil {
			pub.Close()
		}
		hs.Close()
		<-ran
		<-bgDone
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = hs.Shutdown(shutdownCtx)
	if pub != nil {
		pub.Shutdown(shutdownCtx)
	}
	<-ran // sessions closed
	<-bgDone
	// the background databases close on return
	return err
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
