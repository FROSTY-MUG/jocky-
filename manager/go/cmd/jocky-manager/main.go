// ==============================================================================
// JOCKY Manager - scaffolded HTTP service
//
// Purpose:
//   Step 3 scaffold only. Exposes a single /health endpoint on :8080 that
//   reports the service is present but has no STEP 2B functionality yet, and
//   shuts down cleanly on SIGINT/SIGTERM. No agent, tenant, or policy logic
//   is implemented here - that is deliberately deferred to STEP 3.
//
// Inputs:
//   -addr <host:port>   Listen address (default ":8080").
//
// Outputs:
//   HTTP GET /health  -> 200 {"status":"not_implemented", ...}
//   All other paths   -> 404 {"error":"not_found"}
//   Startup and shutdown messages on stdout/stderr.
//
// Exit Codes:
//   0 - Clean shutdown after SIGINT or SIGTERM.
//   1 - Invalid flags, or failure to bind the listen address.
//
// Blueprint Section:
//   §5 Manager & Cloud (scaffold for STEP 3).
// ==============================================================================
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address for the manager HTTP service")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", notFoundHandler)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Shut down cleanly when the process manager asks us to stop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Printf("shutdown signal received, draining connections")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("jocky-manager scaffold listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "error: server failed: %v\n", err)
		os.Exit(1)
	}
	log.Printf("jocky-manager scaffold stopped cleanly")
	os.Exit(0)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "not_implemented",
		"detail": "jocky-manager is a STEP 3 scaffold; no functionality in STEP 2B",
	})
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "not_found"})
}
