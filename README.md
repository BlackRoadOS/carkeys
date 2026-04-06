# CarKeys

*Grab your keys. You're not going anywhere without them.*

Unified credential vault and device registry. One secure keychain for every login, API token, passkey, and device across The BlackRoad.

## The Ride

Grab your CarKeys. Every login, every token, every device — one keychain, always fresh. You're not going anywhere without them.

## What It Does

Master credential manager that handles authentication, API key storage, device trust scoring, and session management across all 14 BlackRoad products. CarKeys is the ignition — nothing starts without it.

## Integrations

| Service | Role |
|---------|------|
| **Clerk** | Identity provider — user auth, SSO, session management |
| **Cloudflare D1** | Credential metadata, device registry |
| **Cloudflare KV** | Session token cache, fast auth lookups |
| **Stripe** | Subscription tier lookup for access control |
| **RoadChain** | Immutable audit log of every key use and rotation |

## Features

- Single sign-on across all BlackRoad products via Clerk
- API key generation, storage, and automatic rotation
- Device fingerprinting and trust scoring
- Family/team profiles with scoped permissions
- Time-limited guest keys for contractors or AI agents
- RoadChain-stamped audit trail for every credential event
- Zero-knowledge architecture — credentials encrypted on-device

## Status

**LIVE** — 94 lines (expanding) | [carkeys.blackroad.io](https://carkeys.blackroad.io)

## How It Powers The BlackRoad

CarKeys is the ignition. You grab them first thing every morning, and every other product starts only after CarKeys authenticates you. No keys, no ride.

---

Part of [BlackRoad OS](https://blackroad.io) — Remember the Road. Pave Tomorrow.
