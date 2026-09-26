# JOCKY Manager (Go)

STEP 2B scaffold for the manager service. It runs, serves a health endpoint,
and shuts down cleanly — but implements no manager logic. Tenancy, policy
distribution, and artifact approval are deferred to STEP 3.

Note: a separate Rust manager lives at `manager/` (the `jocky-manager` crate).
This Go service is the optional lightweight alternative described in the
blueprint; it is not a replacement.

## What is here

| Path | Purpose |
|---|---|
| `go.mod` | Module `github.com/FROSTY-MUG/jocky/manager/go`. |
| `cmd/jocky-manager/main.go` | HTTP service on `:8080`. |

## Build and verify

Requires Go 1.22+ (Windows, Linux, or macOS).

```bash
cd manager/go
go build ./...
go vet ./...
go run ./cmd/jocky-manager -addr :8080
```

Then:

```bash
curl http://127.0.0.1:8080/health
# {"status":"not_implemented","detail":"..."}
```

`SIGINT`/`SIGTERM` triggers a graceful drain (10s timeout) and exit code 0.

## Why Go

The manager is I/O-bound (API serving, artifact polling) rather than
compute-bound. Go gives a single static binary with no runtime dependencies,
which suits container deployment and CI.

## Status

SCAFFOLD — builds, vets, serves `/health`, shuts down cleanly. No STEP 2B
functionality; the endpoint returns `{"status":"not_implemented"}` by design.
