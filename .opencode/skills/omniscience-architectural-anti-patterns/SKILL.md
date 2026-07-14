---
name: omniscience-architectural-anti-patterns
description: Identifies deep structural and design flaws in enterprise microservices, distributed databases, and CDN topologies.
---

# Architectural Anti-Patterns (The Hidden Flaws)

This skill dictates how the Swarm Commander must view a target not as a collection of endpoints, but as an interconnected ecosystem of state machines.

## Core Knowledge Areas

### 1. HTTP Desync and CDN Poisoning
Do not just look for XSS. Look at how the frontend CDN (Cloudflare/Akamai) communicates with the backend load balancer (NGINX/HAProxy).
- **The Anti-Pattern**: If the CDN normalizes URL paths differently than the backend (e.g., handling %2f or ; differently), you can bypass all WAF/Access Control rules.
- **The Attack**: Send malformed Transfer-Encoding or Content-Length headers to desynchronize the connection pool and poison the cache for other users.

### 2. Microservice Authentication Desync
- **The Anti-Pattern**: The Auth service validates a JWT using RS256, but the internal Resource service blindly accepts HS256 (symmetric) using the public key as the secret.
- **The Attack**: Never assume internal microservices trust each other perfectly. Always attempt to spoof JWTs assuming the internal microservice is using a weaker validation library than the edge gateway.

### 3. Distributed Database Race Conditions
- **The Anti-Pattern**: Eventual consistency in Cassandra or MongoDB. If a user withdraws funds, the state might take 50ms to propagate across all nodes.
- **The Attack**: Do not send requests sequentially. Use HTTP/2 multiplexing (single TCP connection, multiple streams) to hit the endpoint 100 times in the exact same millisecond to trigger a Time-of-Check to Time-of-Use (TOCTOU) race condition before the database locks the row.
