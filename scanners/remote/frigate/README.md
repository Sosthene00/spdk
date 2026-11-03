# frigate — remote silent-payment scanner backend

`frigate` is a remote-scanner backend for spdk. It connects to an electrum
server speaking the Frigate silent-payments extension — a full Frigate server
or a single-user `friglet` — subscribes the wallet's scan key, and turns the
server's silent-payment notifications into local `ScanResult`s. The wire side
is the `electrum_streaming_client` (ESC); the silent-payment scan/tweak math
runs locally, only the subscription crosses the network.

Examples live in `examples/`; they connect to `FRIGATE_URL` (default
`127.0.0.1:50001`, plain TCP — or `ssl://host:port` for TLS).

## Trust model

Read this before pointing the scanner anywhere but localhost.

- **The scan private key is SENT to the server.** This is the Frigate
  remote-scanner model: the server derives the silent-payment tweaks and
  reports matching outputs, so it learns everything the scan key knows. This
  matches the BIP-352 index-server spec: the service is trusted, and a user
  should rotate the wallet after leaving a hosted service.
- **TLS (`ssl://`) is strongly recommended off-LAN.** `FrigateClient::connect`
  speaks plain TCP for `host:port` and verified TLS for `ssl://host:port`; the
  scan key crosses the wire on every subscribe, so anything outside a trusted
  LAN should be reached over `ssl://`.
- **The server-returned `start_height` is authoritative** for where the
  delivered history begins (it can differ from the requested start; the
  scanner logs both).
- **Reorgs and reconnects can re-deliver history.** The server re-sends the
  subscription history after a reconnect, so the same discovery can arrive
  more than once — wallets must dedupe by outpoint.
- **Single-user friglet instances answer with their own wallet snapshot
  regardless of the keys sent** (verified 2026-11-03). A friglet serves the
  wallet it was launched with: point the scanner at the matching wallet or at
  a real Frigate server, or you will scan someone else's snapshot.
