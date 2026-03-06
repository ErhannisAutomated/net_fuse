# NetFuse

A distributed, peer-to-peer FUSE filesystem. Files are stored as content-addressed blobs (SHA-256), metadata is synchronized across nodes using vector clocks, peers are discovered automatically via mDNS, and data is transferred over QUIC with mutual TLS.

## Features

- **Automatic peer discovery** — mDNS (`_netfuse._udp.local.`); no configuration needed on a LAN
- **Metadata sync** — vector-clock conflict detection, flood-fill broadcast, full sync on connect
- **Lazy blob transfer** — file content is fetched from peers on first read and cached locally
- **Cache eviction** — two-tier (soft/hard) size limits plus age-based eviction; last-copy safety
- **Peer authorization** — whitelist/blacklist with persistent storage; session-only decisions also supported
- **HTTPS web interface** — browse, upload, download, create folders, delete; certificate-based auth; music player with MediaSession support
- **Read-only viewer endpoint** — separate port, separate cert category; intended for restricted environments
- **Deletion propagation** — per-peer last-known state is propagated transitively so deletions are inferred across nodes that never connected directly (configurable)

## Requirements

- Linux (FUSE support required)
- `libfuse3` — e.g. `apt install fuse3` on Debian/Ubuntu
- Rust 1.85+ (edition 2024)

## Building

```sh
cargo build --release
```

The binary is at `target/release/net_fuse`.

## Quick Start

```sh
mkdir ~/mnt
net_fuse --mount ~/mnt --web-port 8443
```

On first run, a TLS identity and node ID are generated and stored in the data directory. The node registers itself via mDNS and begins browsing for peers.

The web interface is available at `https://localhost:8443`. Because it uses a self-signed certificate, you will need to enroll a client certificate before you can use it:

```
Enroll at: https://localhost:8443/enroll
```

Follow the enrollment flow: the page shows a token, the server prints a matching code to the console, submit both to receive a client certificate, then import it into your browser.

## CLI Reference

```
Usage: net_fuse [OPTIONS]

Options:
  -m, --mount <PATH>              Mount point (required)
  -d, --data-dir <PATH>           Data directory (default: platform app-data dir)
  -n, --name <NAME>               Node name (default: hostname)
  -p, --port <PORT>               QUIC listen port (default: 4433)
      --web-port <PORT>           HTTPS web interface port (default: 8443)
      --viewer-port <PORT>        Read-only viewer endpoint port (disabled by default)
      --allow-other [<BOOL>]      Allow other users to access the mount
      --cache-soft-limit <BYTES>  Soft eviction threshold (default: 5 GiB)
      --cache-hard-limit <BYTES>  Hard eviction threshold (default: 10 GiB)
      --cache-max-age <SECS>      Max blob age for soft eviction (default: 7 days)
      --eviction-interval <SECS>  Time between eviction cycles (default: 5 min)
      --propagate-peer-states [<BOOL>]
                                  Propagate per-peer file states transitively (default: true)
      --config <PATH>             Config file path (default: ~/.config/net_fuse/config.toml)
  -h, --help                      Print help
```

## Config File

All CLI options can be set in a TOML config file. The default location is `~/.config/net_fuse/config.toml` (Linux). CLI arguments take precedence.

```toml
mount    = "/home/alice/mnt"
name     = "alice-laptop"
port     = 4433
web_port = 8443

# Read-only viewer endpoint (disabled when absent)
# viewer_port = 9443

# Cache limits
cache_soft_limit = 5368709120   # 5 GiB
cache_hard_limit = 10737418240  # 10 GiB
cache_max_age    = 604800       # 7 days (seconds)

# Set to false if sync message size is a concern; risks file resurrection
propagate_peer_states = true
```

## Peer Authorization

When a new peer is discovered on the LAN, its certificate fingerprint is presented for review. The console prompts:

```
--- New peer awaiting authorization ---
  Our fingerprint:  SHA256:a1b2c3d4e5f6...
  Peer fingerprint: SHA256:9f8e7d6c5b4a...
  (w)hitelist | (s)ession-allow | (i)gnore-session | (b)lacklist
>
```

| Key | Effect |
|-----|--------|
| `w` | Whitelist — persistent, survives restarts |
| `s` | Session-allow — connected for this run only |
| `i` | Session-ignore — rejected for this run only |
| `b` | Blacklist — persistent rejection |

When multiple peers are pending, prefix the command with a fingerprint prefix: `w a1b2`.

Decisions are stored in `{data_dir}/peer_auth.json`.

## Web Interface

The HTTPS web interface (`--web-port`) provides:

- Directory browsing and navigation
- File upload and download
- Folder creation and deletion
- Music player with queue, seek, loop modes, and MediaSession (global media keys)
- LocalStorage-backed directory cache (stale-while-revalidate, 5-minute TTL)

### Enrollment

Client certificates are required. Visit `/enroll`, enter the token shown on the page plus the code printed to the console, and import the returned `.pem` file into your browser or OS certificate store.

### Read-Only Viewer Endpoint

Start with `--viewer-port <PORT>` (or `viewer_port` in config). This endpoint uses the same HTML interface but disables all write operations. Viewer certificates are a separate category from full network members — they grant read access on that node only, not membership in the distributed filesystem.

Enroll a viewer certificate at `/enroll-viewer` on either the main port or the viewer port.

## Data Directory Layout

```
{data_dir}/
  metadata.db       — SQLite: file entries, vector clocks, blob registry
  node_cert.der     — Node TLS certificate (DER)
  node_key.der      — Node TLS private key (DER)
  peer_auth.json    — Peer whitelist, blacklist, and viewer certs
  blobs/
    ab/
      abcdef...     — Content-addressed blob files (first 2 hex chars = subdir)
```

Default data directory: `~/.local/share/net_fuse` (Linux).

## Logging

Logging is controlled via the `RUST_LOG` environment variable (default: `info`).

```sh
RUST_LOG=debug net_fuse --mount ~/mnt
```

The `mdns-sd` library can produce verbose output on machines with many virtual network interfaces (tiebreaking, AAAA record messages). To suppress it:

```sh
RUST_LOG=info,mdns_sd=warn net_fuse --mount ~/mnt
```

## Notes

- **Deletion inference** — With `propagate_peer_states = true` (default), each node tracks the last-known state of every file from every peer and propagates this transitively during sync. This allows a deletion on node A to be inferred by node C even if they never connected directly, as long as A connected to B and B connected to C. Disabling this trades correctness (risk of file resurrection) for smaller sync messages.
- **No timeout on blob fetch** — A slow or unreachable peer can stall a FUSE read. This is a known limitation.
- **Self-signed TLS** — Peer identity is verified by certificate fingerprint exchange at the application level, not by a CA chain. The `peer_auth.json` whitelist is the trust anchor.
