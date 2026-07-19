package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/sync/errgroup"
)

var (
	// default build fields populated by GoReleaser
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	cfgFile := flag.String("config", "settings.env", "Path to config file")
	showHelp := flag.Bool("help", false, "Display help")
	showVersion := flag.Bool("version", false, "Display build information")

	flag.Parse()

	switch {
	case *showVersion:
		fmt.Printf("%-10s %s\n", "version:", version)
		fmt.Printf("%-10s %s\n", "commit:", commit)
		fmt.Printf("%-10s %s\n", "date:", date)
		os.Exit(0)
	case *showHelp:
		flag.PrintDefaults()
		os.Exit(0)
	}

	// optionally populate environment variables with config file
	if err := godotenv.Load(*cfgFile); err != nil {
		fmt.Printf("Config file (%s) not found, defaulting to env vars for app config...\n", *cfgFile)
	} else {
		fmt.Printf("Successfully loaded config file (%s)\n", *cfgFile)
	}
}

func main() {
	// BENCO: checked before anything binds a socket, so a misconfigured server
	// never reaches a state where some listeners are up and the operator's
	// expectations are half-met. See the WebAPI note below.
	if os.Getenv("ENABLE_WEBAPI") != "" {
		fmt.Println("ENABLE_WEBAPI is set, but the WebAPI is removed from this fork " +
			"(it authenticates any non-empty password — see CLAUDE.md). Unset it to start.")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deps, err := MakeCommonDeps()
	if err != nil {
		fmt.Printf("startup failed: %s\n", err)
		os.Exit(1)
	}

	g, ctx := errgroup.WithContext(ctx)

	oscar := OSCAR(deps)
	g.Go(oscar.ListenAndServe)

	kerb := KerberosAPI(deps)
	g.Go(kerb.ListenAndServe)

	api := MgmtAPI(deps)
	g.Go(api.ListenAndServe)

	toc := TOC(deps)
	g.Go(toc.ListenAndServe)

	// BENCO: the WebAPI server is removed from this fork and cannot be enabled.
	//
	// state/webapi_auth.go's AuthenticateUser returns the user for ANY non-empty
	// password — it carries an explicit "TODO: In production, verify password
	// hash here" — and cmd/server/factory.go binds it to 0.0.0.0:9000 hardcoded,
	// ignoring the listener config entirely. That combination is an
	// authentication bypass reachable on every interface. It is upstream
	// work-in-progress rather than something broken, but it ships in v0.24.0 and
	// BENCO has no use for it.
	//
	// Setting ENABLE_WEBAPI is a hard startup failure rather than a no-op: an
	// operator who sets it believes a web API is listening, and quietly ignoring
	// them would leave that belief intact. That check runs at the top of main,
	// before any socket is bound. If this fork ever wants the WebAPI, the
	// password check has to be real first.

	// Start ICQ Legacy server if enabled
	icqLegacy := ICQLegacy(deps)
	if deps.cfg.ICQLegacy.Enabled {
		g.Go(icqLegacy.ListenAndServe)
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = oscar.Shutdown(shutdownCtx)
	_ = kerb.Shutdown(shutdownCtx)
	_ = api.Shutdown(shutdownCtx)
	_ = toc.Shutdown(shutdownCtx)
	if deps.cfg.ICQLegacy.Enabled {
		_ = icqLegacy.Shutdown(shutdownCtx)
	}

	if err = g.Wait(); err != nil {
		deps.logger.Error("server initialization failed", "err", err.Error())
		os.Exit(1)
	}
}
