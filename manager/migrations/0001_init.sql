-- Initial JOCKY DFIR Management Database Schema
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    consent_token_hash BYTEA NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scripts (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    source_hash BYTEA NOT NULL,
    build_id TEXT NOT NULL,
    diversification_seed BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    sbom JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    script_id UUID REFERENCES scripts(id),
    agent_id UUID REFERENCES agents(id),
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    retry_count INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY,
    job_id UUID REFERENCES jobs(id),
    agent_id UUID REFERENCES agents(id),
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence JSONB NOT NULL,
    mitre TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
