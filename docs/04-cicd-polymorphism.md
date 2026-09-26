# 04 — Polymorphic CI/CD Pipeline

Platform: **GitHub Actions** (OIDC-based, no long-lived secrets in the runner). Mirror pipeline definition for GitLab CI is kept in `ci/gitlab-ci.yml.tmpl` for portability, but GitHub is primary.

---

## 1. Pipeline overview

```
push/PR
  │
  ├─ stage: gate            (2 min)
  │    fmt · clippy -D warnings · cargo-deny · forbidden-API grep gate
  │    compile-fail denylist conformance suite
  │
  ├─ stage: build-core      (12 min, matrix: linux + windows)
  │    jockyc · agent-win · agent-linux · manager · dashboard
  │
  ├─ stage: test            (20 min)
  │    unit · integration · jocky-difftest (all variants vs VM) · fuzz-smoke (10 min)
  │
  ├─ stage: diversify       (15 min, matrix: 8 variants × 2 targets)
  │    jockyc build --seed ${{ github.run_id }}-${{ matrix.variant }} --variant-count 8
  │    jocky-diversity-report → fails if diversity floor not met
  │    jocky-difftest → all 8 variants must be semantically identical
  │
  ├─ stage: attest          (6 min)
  │    sbom (CycloneDX) · sign via KMS · tlog append · reproducible-build re-run check
  │
  ├─ stage: publish         (4 min)
  │    upload artifacts to s3://jocky-artifacts/ · register build in manager
  │
  └─ stage: deploy          (manual gate for prod, auto for lab)
       canary rollout → health check → fleet rollout → auto-rollback on failure
```

Total ~60 min for a full run; PR runs skip `diversify`/`attest`/`publish` (fast path ~35 min) unless the PR touches `compiler/` or `agent/`.

---

## 2. The diversification matrix

```yaml
# .github/workflows/build.yml (abridged, real)
name: jocky-build
on:
  push: { branches: [main] }
  pull_request:

permissions:
  id-token: write      # OIDC for KMS + artifact upload
  contents: read

env:
  VARIANT_COUNT: 8
  JOCKY_ENV: lab

jobs:
  diversify:
    if: github.event_name == 'push' || contains(github.event.pull_request.labels.*.name, 'full-build')
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        target: [x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu]
        variant: [0,1,2,3,4,5,6,7]
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - name: Cache LLVM + cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-${{ matrix.target }}-${{ hashFiles('**/Cargo.lock') }}

      - name: Build variant
        run: |
          jockyc build scripts/ \
            --target ${{ matrix.target }} \
            --seed "${{ github.run_id }}-${{ matrix.variant }}" \
            --variant-index ${{ matrix.variant }} \
            --variant-count ${{ env.VARIANT_COUNT }} \
            --mode native,bytecode \
            --emit-dir out/${{ matrix.target }}/v${{ matrix.variant }} \
            --diversity-floor cfg=0.2,import=0.15,entropy=7.6 \
            --deterministic

      - name: Verify semantic equivalence across variants
        run: jocky-difftest --corpus scripts/ --variants out/${{ matrix.target }}/v*/ \
             --fixture fixtures/host-snapshot-lab.json \
             --require-identical

      - name: Diversity report
        run: jocky-diversity-report --dir out/${{ matrix.target }} --format json > diversity.json
              && jocky-diversity-report --dir out/${{ matrix.target }} --enforce-floor

      - name: SBOM (CycloneDX)
        run: |
          cargo cyclonedx --format json --override-filename sbom.cdx.json
          syft dir:. -o cyclonedx-json=sbom-deps.cdx.json
          jq -s '.[0].components += .[1].components | .[0]' sbom.cdx.json sbom-deps.cdx.json > sbom.merged.cdx.json

      - name: Sign manifests (KMS, no key export)
        run: |
          for f in out/${{ matrix.target }}/v${{ matrix.variant }}/*.jkm; do
            jocky-sign --file "$f" \
              --kms-key "${{ vars.JOCKY_BUILD_KMS_KEY }}" \
              --aws-oidc-role "${{ vars.JOCKY_SIGN_ROLE_ARN }}" \
              --signature-out "$f.sig"
          done

      - name: Append to transparency log
        run: jocky-tlog append --dir out/${{ matrix.target }}/v${{ matrix.variant }} \
             --log https://tlog.jocky.internal --mirror r2://jocky-tlog-mirror

      - name: Reproducibility check (second runner)
        run: |
          jockyc build scripts/ --seed "${{ github.run_id }}-${{ matrix.variant }}" \
            --target ${{ matrix.target }} --variant-index ${{ matrix.variant }} \
            --deterministic --emit-dir out-repro/
          diff -r out/${{ matrix.target }}/v${{ matrix.variant }} out-repro/ \
            || (echo "NON-DETERMINISTIC BUILD" && exit 1)

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.JOCKY_ARTIFACT_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}

      - name: Publish artifacts
        run: |
          BUILD_ID="${{ github.run_id }}-${{ matrix.variant }}-${{ matrix.target }}"
          aws s3 cp --recursive out/${{ matrix.target }}/v${{ matrix.variant }}/ \
            "s3://jocky-artifacts/${{ vars.JOCKY_TEAM }}/$BUILD_ID/" \
            --sse aws:kms --sse-kms-key-id "${{ vars.JOCKY_BUNDLE_KMS_KEY }}"
          aws s3 cp sbom.merged.cdx.json \
            "s3://jocky-artifacts/${{ vars.JOCKY_TEAM }}/$BUILD_ID/sbom.cdx.json"

      - name: Register build with manager
        run: |
          jocky-cli builds register \
            --manager "${{ vars.JOCKY_MANAGER_URL }}" \
            --build-id "${{ github.run_id }}-${{ matrix.variant }}-${{ matrix.target }}" \
            --manifest out/${{ matrix.target }}/v${{ matrix.variant }}/manifest.cbor \
            --sbom-url "s3://jocky-artifacts/.../sbom.cdx.json" \
            --oidc-token "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
```

### 2.1 Variant count: why 8 per target, per release

- Each agent instance pins **one** variant at enrollment (chosen by `variant_index = hash(agent_id) % count`). Different hosts therefore run structurally different binaries from the same semantic source.
- 8 variants × 2 targets × ~12 scripts = 192 signed artifacts per release, ~40 MB total. Storage is trivial; the auditability cost is one transparency-log leaf each.
- Variants are **not** rotated per-run for a given agent (stability matters for incident reconstruction). Rotation happens on **agent version bump**, with the previous variant hash retained in the registry so historical bundles remain attributable.

---

## 3. Diversity floor enforcement

`jocky-diversity-report` computes, across all variants of the same script:

| Metric | Threshold | Why |
|---|---|---|
| CFG block-order Kendall τ (pairwise max) | ≤ 0.20 | Proves block permutation actually happened |
| Import-set Jaccard distance (pairwise min) | ≥ 0.15 | Proves import table permutation happened |
| Code-section byte-level LCS distance (pairwise min) | ≥ 0.85 | Proves instruction substitution + layout changed substantially |
| `.rdata` string-section entropy (min) | ≥ 7.6 bits/byte | Proves string encryption ran |
| Entry-point offset uniqueness | all distinct | Proves entry randomization ran |
| Section-name set uniqueness | all distinct | Proves header randomization ran |

A build that fails any floor **fails CI**. This is the anti-regression mechanism: it prevents a future refactor from silently making variants identical (which would be the actual failure mode that makes JOCKY look like a toy).

---

## 4. Signing & key custody

| Key | Storage | Access | Rotation |
|---|---|---|---|
| `K_build` (Ed25519) | AWS KMS asymmetric (`ECC_NIST_EDWARDS25519`) or GCP KMS | GitHub OIDC → assume `JOCKY_SIGN_ROLE_ARN` → `kms:Sign` only; **`kms:GetPublicKey` restricted to the verifier role** | 90 days; old key remains valid for verification; `key_id` is in every signature block |
| `K_team` (Ed25519, cosign) | Vault transit engine | Team lead + architect dual-control for key use | 180 days |
| `K_manager_root` (Ed25519, consent tokens) | Vault transit, HSM-backed if available | Manager service identity only; `sign` permission scoped by token-policy path | 180 days, with overlapping validity |
| Agent identity keys | TPM/CNG (Win), TPM or 0600 file (Linux) | Agent process only | On re-enrollment |
| Bundle envelope keys | Ephemeral X25519 per job | Agent + manager, derived from job token | Per job |

**Rule: no private key ever exists in a CI runner's memory.** Signing is a KMS API call. The reproducibility check runs on a *second, independent runner* so a compromised runner cannot fake determinism.

**Vault policy for `K_team` (example):**

```hcl
path "transit/sign/jocky-team-c4-ir" {
  capabilities = ["update"]
  required_parameters = ["input"]
  allowed_parameters = { "input" = [] }
}
path "transit/keys/jocky-team-c4-ir" {
  capabilities = ["read"]     # public key only, for verification
}
# Deliberately absent: export, delete, rotate (rotation is a separate break-glass path
# requiring two approvers via Vault's control-group feature).
```

---

## 5. Static gates (the "forbidden API" wall)

A CI step greps the entire codebase for primitives that must never appear, and fails on any hit outside a documented allowlist file with a justification comment:

```bash
#!/usr/bin/env bash
# ci/forbidden-api.sh
set -euo pipefail
FORBIDDEN=(
  # remote process manipulation
  'WriteProcessMemory' 'NtWriteVirtualMemory' 'CreateRemoteThread' 'NtCreateThreadEx'
  'QueueUserAPC' 'SetThreadContext' 'NtMapViewOfSection.*AtAddress'
  'ptrace' 'process_vm_writev'
  # persistence
  'CreateService' 'RegSetValueEx.*\\\\Run' 'schtasks.*\/create' 'systemd.*enable'
  'crontab.*-e' 'rc.local' 'launchctl.*load'
  # credential access
  'MiniDumpWriteDump' 'sekurlsa' 'lsass.*dump' 'SAM' 'SECURITY\\Policy\\Secrets'
  # kernel modification
  'ZwLoadDriver' 'NtLoadDriver' 'MmMapIoSpace' 'PsSetCreateProcessNotifyRoutine' # (only read-side enum allowed)
  # privilege escalation
  'SeDebugPrivilege.*Enable' 'ImpersonateLoggedOnUser' 'AdjustTokenPrivileges.*SE_DEBUG'
)
ALLOWLIST="ci/forbidden-api.allowlist"
fail=0
for pat in "${FORBIDDEN[@]}"; do
  while IFS= read -r hit; do
    grep -qF "$hit" "$ALLOWLIST" || { echo "FORBIDDEN API: $hit"; echo "  $hit"; fail=1; }
  done < <(grep -rIn --include='*.rs' --include='*.cpp' --include='*.h' -E "$pat" . || true)
done
[ "$fail" -eq 0 ] || { echo "Static gate FAILED"; exit 1; }
```

`ci/forbidden-api.allowlist` currently contains exactly one entry — `NtQueryVirtualMemory` (read-only, needed for memory triage) — with a comment naming the reviewer and the ticket. Every addition to the allowlist requires architect sign-off, which makes the wall meaningful rather than decorative.

Additional gates: `cargo-deny` (advisories, licenses, duplicate versions, banned crates list including `winapi` in favor of `windows-rs`), `cargo-geiger` (unsafe-code census with a per-crate ceiling), `cargo-audit`, `semgrep` with a JOCKY ruleset, and `trivy fs` for dependency CVEs.

---

## 6. Deployment, versioning, rollback

### 6.1 Versioning

`<major>.<minor>.<patch>+build.<run_id>` — e.g. `1.4.2+build.8814`. The manifest carries `build_id`, `commit`, `variant_index`, and `semantics_hash`. Two variants of the same source share `semantics_hash`; that is how the manager knows a job's results are comparable across hosts running different variants.

### 6.2 Rollout

```
1. lab-canary   → 1 designated lab VM per platform, auto, health gate: 3 heartbeats + 1 successful job
2. lab-fleet    → all lab VMs, auto after canary passes for 30 min
3. prod-canary  → 1 production agent (only with change ticket + explicit `--allow-prod` flag)
4. prod-fleet   → 10% → 50% → 100%, 20 min soak between steps
```

Health gate signals: heartbeat present, enrollment intact, last job succeeded, no `verification_failure` journal entries, agent self-hash matches manifest, memory RSS within 2× baseline.

### 6.3 Rollback

- Every agent keeps the **previous** signed variant on disk in `.../versions/<build_id>/` (agent binaries only — modules are always fetched fresh).
- Rollback = manager sets `agent.pinned_version` to the previous build and pushes a `switch_version` command over the control channel; the agent verifies the target version's manifest (it is already in its local registry) and swaps.
- Automatic rollback trigger: > 2 min heartbeat loss in > 10% of a rollout group, or > 5% job failure rate in the group, or any `verification_failure` cluster.
- Module rollback is instant: the manager simply stops issuing consent tokens for the bad `build_id`; the revocation list is pushed in the heartbeat response (`revocation_list_version`) and the agent refuses any module whose `build_id` is on it.

### 6.4 Kill switch

A single manager action `POST /v1/admin/halt` sets a global flag that (a) stops all token issuance, (b) pushes `HALT` on the next heartbeat, and (c) causes every agent to stop accepting modules, flush its spool, and remain heartbeat-only. Reversible with `POST /v1/admin/resume`. Both actions are audit-logged and require two-person approval (Vault control group).

---

## 7. Supply-chain hardening

| Control | Implementation |
|---|---|
| Pinned toolchain | `rust-toolchain.toml` exact version; LLVM version pinned in `compiler/llvm-version.txt`; container images by digest |
| Lockfiles | `Cargo.lock` committed; `npm ci` with `package-lock.json`; `--frozen-lockfile` |
| Action pinning | All GitHub Actions pinned to full commit SHAs, verified by `zizmor` in CI |
| Provenance | `actions/attest-build-provenance` SLSA v1 build provenance for every artifact |
| SBOM | CycloneDX merged (cargo + syft), published next to artifacts, referenced from the manifest |
| Dependency review | `cargo-deny` + GitHub dependency-review-action on PRs; deny on any new `unsafe`-heavy crate without review |
| Vendored vulnerable-driver hashlist | Pinned by commit hash in `agent/data/vuln_drivers.lock`, updated only via a signed PR from a maintainer, never fetched at runtime |
| Build isolation | CI runners are ephemeral; no self-hosted runners for signing; artifact bucket write-only from CI, read-only for the manager |