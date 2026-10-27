# Coordination API v1

HTTPS for remote clients; explicit loopback-only HTTP development mode. Authentication:
`Authorization: Bearer <token>`. POST network/peer requests require `application/json`.
No secrets in query strings. No browser cross-origin calls. Responses use `Cache-Control: no-store`.

| Method | Path | Credential | Body / result |
| --- | --- | --- | --- |
| GET | `/healthz` | none | health; `storage` is `file` or `ephemeral` |
| POST | `/v1/networks` | server admin | `{name}` → networkId, name, ownerToken |
| POST | `/v1/networks/{id}/invites` | network owner | empty → networkId, inviteToken, expiresAt |
| POST | `/v1/networks/{id}/peers` | one-use invite | `{name,publicKey,endpoint}` → networkId, peerId, address, peerToken |
| GET | `/v1/networks/{id}/peers` | owner or current member | networkId, peers[] |
| DELETE | `/v1/networks/{id}/peers/{peerId}` | owner | removes API membership; manual profile refresh still required |

UUID identifiers are canonical lowercase. Names are 1–64 characters, without
control/format characters or surrounding whitespace. WireGuard public keys encode
32 bytes in standard Base64; low-order and noncanonical points are rejected.
Optional endpoint is an empty string or literal unicast IPv4:port. Port is 1–65535.

Limits: request body 8192 bytes; client response 131072 bytes; JSON nesting 12;
32 networks; 64 active peers and 32 active invitations per network; invitations
expire at the ten-minute deadline. Global token bucket: burst 100, refill 10/sec.

Error bodies are `{code,message}`; statuses include 400, 401, 403, 404, 409, 413,
415, 429 and 503 (`storage_unavailable`: the change was not saved and was rolled back). Internal exception details are not returned. Mutating requests are not
automatically retried: a lost enrollment response requires owner-assisted recovery.
