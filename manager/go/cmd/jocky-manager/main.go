// ==============================================================================
// JOCKY Manager - Central Management & Cloud Relay Service (STEP 3)
//
// Purpose:
//   Coordinates endpoint agents, issues cryptographic consent tokens,
//   manages forensic jobs, ingests telemetry/threat findings, and maintains
//   a tamper-evident append-only cryptographic audit log.
//
// Inputs:
//   -addr <host:port>   Listen address (default ":8080").
//
// Blueprint Section:
//   §5 Manager & Cloud; §0.2 Safety Model; §0.3 Consent Tokens.
// ==============================================================================
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FROSTY-MUG/jocky/manager/go/internal/api"
	"github.com/FROSTY-MUG/jocky/manager/go/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address for the manager HTTP service")
	flag.Parse()

	dataStore := store.NewStore()
	apiServer := api.NewServer(dataStore)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Clean shutdown handler
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Printf("[JOCKY-MANAGER] Shutdown signal received, draining active connections...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[JOCKY-MANAGER] Graceful shutdown error: %v", err)
		}
	}()

	log.Printf("[JOCKY-MANAGER] Central Management Service v0.1 started on %s", *addr)
	log.Printf("[JOCKY-MANAGER] Ready for agent telemetry, consent token issuance, and DFIR dashboard queries")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "error: server failed: %v\n", err)
		os.Exit(1)
	}
	log.Printf("[JOCKY-MANAGER] Server stopped cleanly")
	os.Exit(0)
}
