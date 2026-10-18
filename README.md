# VAID across clouds: Northwind Platform &rarr; Harbor Ops

A working demo of VAID carrying agent identity across a boundary where nothing
else does: two organisations, two clouds, no shared IAM, no federation, no
network peering, no secrets in common.

## 60 seconds

**Org A — Northwind Platform** runs an infrastructure agent on Google Cloud
(Cloud Run, `europe-west1`). It mints that agent a VAID credential: a signed
statement of who it is, what trust domain issued it, what it is scoped to do,
and when it expires. Northwind publishes its public key over plain HTTPS at
`/.well-known/vaid-keys.json`, the way any server publishes anything it wants
a stranger to be able to check.

**Org B — Harbor Ops** runs a deployment agent on AWS (Lambda behind a
Function URL, `eu-west-2`). It has never heard of Northwind's IAM, has no
federation agreement with Google Cloud, and holds none of Northwind's
secrets. When a request arrives claiming to come from a Northwind agent,
Harbor Ops:

1. checks Northwind's trust domain against its own allowlist,
2. fetches (or reuses a cached copy of) Northwind's public key,
3. checks the credential's signature,
4. checks it has not expired,
5. checks it has not been revoked (via a status feed it polls and caches),
6. checks the delegation chain is authentic and within the depth it allows,
7. checks the requested resource against its own policy — which is narrower
   than whatever the credential itself claims.

Only then does it accept or refuse, and it signs its own record of the
decision with its own key, independently of anything Northwind can see or
touch.

**Nothing about this needs Google and Amazon to agree on anything.** The
credential and the request are the only things that cross the wire. Org B
decides for itself.

## Architecture

```
                         HTTPS only — no shared IAM, no federation, no secrets
  ┌─────────────────────────────┐                      ┌──────────────────────────────┐
  │  Org A — Northwind Platform │                       │  Org B — Harbor Ops          │
  │  Google Cloud, europe-west1 │                       │  AWS, eu-west-2              │
  │                              │                       │                              │
  │  Cloud Run (min-instances=0)│   credential + request │  Lambda (Function URL)       │
  │  ├─ POST /mint               │ ─────────────────────▶│  ├─ trust-domain allowlist    │
  │  ├─ POST /delegate           │                        │  ├─ cached pubkey fetch       │
  │  ├─ POST /revoke             │  ◀───── pubkey fetch ──│  ├─ signature / expiry        │
  │  ├─ GET /.well-known/        │                        │  ├─ cached revocation status  │
  │  │     vaid-keys.json        │  ◀── revocation poll ──│  ├─ delegation depth/chain    │
  │  ├─ GET /vaid-revocations/   │                        │  ├─ own scope policy          │
  │  │     status                │                        │  └─ signed audit → DynamoDB   │
  │  ├─ signing key: Secret      │                        │     (on-demand, eu-west-2)    │
  │  │   Manager (GCP)           │                        │  signing key: Secrets Manager │
  │  ├─ lineage + revocation:    │                        │     (AWS)                     │
  │  │   Firestore (durable —    │                        │                               │
  │  │   required because        │                        │                               │
  │  │   min-instances=0 means   │                        │                               │
  │  │   the container restarts) │                        │                               │
  │  └─ demo page (static)       │                        │                               │
  └─────────────────────────────┘                        └──────────────────────────────┘
```

## Running the demo

```bash
export ORG_A_URL=https://<northwind cloud run url>
export ORG_B_URL=https://<harbor-ops lambda function url>
./demo-wake.sh   # wakes both sides from scale-to-zero, prints READY
```

Then open `$ORG_A_URL` in a browser. Five buttons, one per scenario; the
crossing view shows every check Harbor Ops makes, in order, with timings.

To redeploy either side:

```bash
GCP_PROJECT=<non-prod project> ./org-a-northwind/deploy.sh
ORG_A_TRUST_DOMAIN=<northwind host> ./org-b-harbor/deploy.sh
```

Both scripts are idempotent.

## What is VAID, and what is this demo's own plumbing

VAID defines the credential: a signed, attenuating, revocable identity for an
agent. It does **not** define how a verifier with no shared infrastructure
learns a stranger's public key or revocation state in the first place — that
is deliberately out of scope of the wire format. This demo's integration
choices for that gap, both visible in the crossing view:

- **Key distribution**: Northwind publishes its public key at a well-known
  HTTPS path; Harbor Ops fetches and caches it. The same pattern WebPKI and
  SPIFFE both use for key distribution — not a VAID invention.
- **Revocation distribution**: Northwind exposes a revocation status feed;
  Harbor Ops polls it and caches the answer for a configurable window
  (default 60s, adjustable live on the demo page), mapped onto VAID's own
  three-state revocation check (clean / revoked / indeterminate — which
  fails closed).

Everything else — signature verification, expiry, delegation depth and
attenuation, lineage — runs through `vaid-mint` 0.11 unmodified.

## Limitations, stated plainly

- Org A's mint/delegate/revoke endpoints have no operator authentication in
  front of them in this demo, so the browser page can call them directly and
  the crossing view shows real network traffic. In production these would be
  behind Org A's own operator auth.
- Org B's Lambda Function URL needed a second resource-policy statement
  (`lambda:InvokeFunction` with condition `InvokedViaFunctionUrl=true`) before
  anonymous requests worked — the `lambda:InvokeFunctionUrl` grant alone was
  not sufficient. `org-b-harbor/deploy.sh` includes it.
- The revocation feed is this demo's own plumbing, not part of the VAID wire
  spec. Said outright in the talk track, not hidden.
