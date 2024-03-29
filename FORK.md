### Fork backports

This v1.9.5-based fork carries the following tunnel-liveness fixes (2026-10-23).
Preserve them when rebasing or updating the vendored checkout:

- [Upstream #1752](https://github.com/slackhq/nebula/pull/1752): register the
  connection-manager watch under the hostmap write lock. A new host must not
  become visible to outgoing traffic before registration and escape monitoring.
- [Upstream #1463](https://github.com/slackhq/nebula/pull/1463): reject duplicate
  and out-of-window encrypted packets without sending `recv_error`. Anti-replay
  rejection and configured receive errors for unknown connections are retained.

Regression coverage: `TestHandshakeManager_TrafficWatchOnPublication`,
`TestHandleEncrypted_*`, and the encrypted in-memory
`TestAuthenticatedReplayKeepsTunnel` (`go test -tags=e2e_testing ./e2e`).
The E2E helpers use this fork's exported `Control.F` and extra `nebula.Main`
UDP-connection argument; these compatibility changes are test-only.

### Handshake recv_error fixes (2026-11-14)

Two fixes for tunnels that churned about once a second under bulk traffic
between two PrivNetwork Macs (`priv/docs/HANDOFF-nebula-tunnel-churn.md`):

- Fork change, not upstream (upstream master still has the race): don't send
  `recv_error` for an index that is our own pending handshake
  (`handleEncrypted`, `outside.go`). A responder makes its new tunnel primary
  in `ixHandshakeStage1` before it sends stage 2, so its traffic can reach the
  initiator first. The initiator answered with `recv_error`, the responder
  closed the new tunnel, and the initiator's tunnel then pointed at a dead
  index, so it was closed too and the handshake started over. Those packets
  are still dropped (there are no keys yet), but the tunnel survives.
  Its upstream form, against master with an e2e test, is branch
  `pending-handshake-recv-error`.
- [Upstream #1811](https://github.com/slackhq/nebula/pull/1811): only delete
  the pending handshake for a vpn ip if it is the hostinfo being deleted
  (`HandshakeManager.unlockedDeleteHostInfo`). `handleRecvError` passes an
  established hostinfo and dropped a newer pending handshake to the same peer.
  Remove when upgrading to nebula v1.11.0+.

Regression coverage: e2e `TestPendingIndexNoRecvError`,
`TestHandleEncrypted_UnknownConnection/own_pending_handshake` and
`TestHandshakeManager_DeleteHostInfoKeepsOtherPending`.

`cmd/nebula`, `cmd/nebula-service` and `service` pass the fork's extra
`nebula.Main` UDP-connection argument (nil) so they build again.
