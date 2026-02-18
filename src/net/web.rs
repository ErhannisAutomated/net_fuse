use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::keys::NodeIdentity;
use crate::metadata::types::{EntryKind, FileEntry};
use crate::metadata::MetadataDb;
use crate::net::peer_auth::PeerAuth;
use crate::store::BlobStore;
use crate::sync::SyncEvent;

static WEB_UI_HTML: &str = include_str!("web_ui.html");

/// Client certificate fingerprint extracted from the TLS connection.
/// `None` means no client certificate was presented.
#[derive(Clone)]
pub(crate) struct ClientFingerprint(pub(crate) Option<String>);

/// Token pair for two-factor enrollment.
struct EnrollmentTokenPair {
    web_token: String,
    console_token: String,
    expires: Instant,
}

/// Shared state for the web server.
pub struct WebServer {
    db: Arc<MetadataDb>,
    store: Arc<BlobStore>,
    peer_auth: Arc<PeerAuth>,
    sync_tx: mpsc::UnboundedSender<SyncEvent>,
    node_id: Uuid,
    enrollment: Mutex<Option<EnrollmentTokenPair>>,
    identity: Arc<NodeIdentity>,
}

type AppState = Arc<WebServer>;

/// Query parameter for path-based endpoints.
#[derive(Deserialize)]
struct PathQuery {
    path: String,
}

/// Enrollment form submission.
#[derive(Deserialize)]
struct EnrollForm {
    web_token: String,
    console_token: String,
}

/// Directory listing entry returned as JSON.
#[derive(Serialize)]
struct LsEntry {
    name: String,
    kind: &'static str,
    size: u64,
    mtime_secs: i64,
    permissions: u32,
}

/// File metadata returned as JSON.
#[derive(Serialize)]
struct MetaResponse {
    path: String,
    kind: &'static str,
    size: u64,
    mtime_secs: i64,
    ctime_secs: i64,
    permissions: u32,
    hash: Option<String>,
}

impl WebServer {
    pub fn new(
        db: Arc<MetadataDb>,
        store: Arc<BlobStore>,
        peer_auth: Arc<PeerAuth>,
        sync_tx: mpsc::UnboundedSender<SyncEvent>,
        node_id: Uuid,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        Self {
            db,
            store,
            peer_auth,
            sync_tx,
            node_id,
            enrollment: Mutex::new(None),
            identity,
        }
    }

    /// Start the HTTPS web server.
    pub async fn run(self: Arc<Self>, port: u16) -> anyhow::Result<()> {
        let rustls_config = self.identity.build_https_config()?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(rustls_config));

        let app = build_router(self.clone());

        let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
        info!(port, "Web server listening");

        loop {
            let (tcp_stream, _remote_addr) = listener.accept().await?;
            let acceptor = tls_acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                // TLS handshake
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, "TLS handshake failed");
                        return;
                    }
                };

                // Extract client cert fingerprint from the TLS session
                let fingerprint = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|cert| crate::cert_fingerprint(cert.as_ref()));
                let client_fp = ClientFingerprint(fingerprint);

                // Wrap the axum router so we can inject the fingerprint extension
                let service = hyper::service::service_fn(
                    move |req: Request<hyper::body::Incoming>| {
                        let mut app = app.clone();
                        let fp = client_fp.clone();
                        async move {
                            use tower::Service;
                            let (mut parts, body) = req.into_parts();
                            parts.extensions.insert(fp);
                            let req = Request::from_parts(parts, Body::new(body));
                            app.call(req).await.map_err(|e| match e {})
                        }
                    },
                );

                let io = TokioIo::new(tls_stream);
                let conn = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                if let Err(e) = conn.serve_connection(io, service).await {
                    tracing::debug!(error = %e, "HTTP connection error");
                }
            });
        }
    }
}

/// Build the axum Router with all routes. Extracted as a standalone function
/// so tests can call handlers directly (via `tower::ServiceExt::oneshot`)
/// without TLS.
pub(crate) fn build_router(state: AppState) -> Router {
    // Enrollment routes — unauthenticated
    let enroll_routes = Router::new()
        .route("/enroll", get(handle_enroll_page))
        .route("/enroll", post(handle_enroll_submit));

    // Authenticated API routes — protected by auth_middleware
    let api_routes = Router::new()
        .route("/", get(handle_index))
        .route("/api/ls", get(handle_ls))
        .route("/api/file", get(handle_download))
        .route("/api/meta", get(handle_meta))
        .route("/api/upload", post(handle_upload))
        .route("/api/file", delete(handle_delete))
        .route("/api/mkdir", post(handle_mkdir))
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024)) // 256 MB upload limit
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .merge(enroll_routes)
        .merge(api_routes)
        .with_state(state)
}

/// Middleware that checks `ClientFingerprint` against PeerAuth.
/// Returns 403 if no valid client cert or not whitelisted.
async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let allowed = req
        .extensions()
        .get::<ClientFingerprint>()
        .and_then(|cf| cf.0.as_ref())
        .map(|fp| {
            matches!(
                state.peer_auth.check(fp),
                crate::net::peer_auth::AuthResult::Allowed
            )
        })
        .unwrap_or(false);

    if allowed {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "Forbidden").into_response()
    }
}

/// Generate a random 6-character alphanumeric token.
fn gen_token() -> String {
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789"; // no confusing chars
    let mut rng = rand::rng();
    (0..6)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

// ---- Enrollment Handlers ----

async fn handle_enroll_page(State(state): State<AppState>) -> impl IntoResponse {
    // Generate a fresh token pair
    let web_token = gen_token();
    let console_token = gen_token();

    println!("\n===================================");
    println!("  Web Enrollment Confirmation Code");
    println!("  Code: {console_token}");
    println!("  Expires in 5 minutes.");
    println!("===================================\n");

    *state.enrollment.lock() = Some(EnrollmentTokenPair {
        web_token: web_token.clone(),
        console_token,
        expires: Instant::now() + std::time::Duration::from_secs(300),
    });

    Html(format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetFuse - Enroll</title>
<style>
body {{ font-family: -apple-system, sans-serif; background: #f5f5f5; display: flex; justify-content: center; padding-top: 80px; }}
.card {{ background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }}
h2 {{ margin-bottom: 16px; color: #2c3e50; }}
p {{ color: #555; margin-bottom: 16px; line-height: 1.5; }}
input[type=text] {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 1.1em; letter-spacing: 4px; text-align: center; margin-bottom: 16px; }}
button {{ width: 100%; padding: 12px; background: #3498db; color: #fff; border: none; border-radius: 4px; font-size: 1em; cursor: pointer; }}
button:hover {{ background: #2980b9; }}
.error {{ color: #e74c3c; margin-bottom: 12px; display: none; }}
</style></head><body>
<div class="card">
<h2>NetFuse Enrollment</h2>
<p>A confirmation code has been printed on the server console. Enter it below to receive your client certificate.</p>
<form method="POST" action="/enroll" id="enrollForm">
<input type="hidden" name="web_token" value="{web_token}">
<div class="error" id="error">Invalid or expired code. Please try again.</div>
<input type="text" name="console_token" placeholder="Enter code" maxlength="6" autofocus>
<button type="submit">Enroll</button>
</form>
</div></body></html>"#
    ))
}

async fn handle_enroll_submit(
    State(state): State<AppState>,
    axum::extract::Form(form): axum::extract::Form<EnrollForm>,
) -> impl IntoResponse {
    // Validate tokens
    let valid = {
        let guard = state.enrollment.lock();
        if let Some(ref pair) = *guard {
            pair.web_token == form.web_token
                && pair.console_token == form.console_token
                && Instant::now() < pair.expires
        } else {
            false
        }
    };

    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<html><body><h2>Invalid or expired enrollment token.</h2><p><a href=\"/enroll\">Try again</a></p></body></html>".to_string()),
        ).into_response();
    }

    // Consume the token pair
    *state.enrollment.lock() = None;

    // Generate client cert
    let short_id = gen_token();
    let client_name = format!("web-{short_id}");
    let (cert_der, key_der) = match NodeIdentity::generate_client_identity(&client_name) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(error = %e, "Failed to generate client identity");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(
                    "<html><body><h2>Failed to generate certificate.</h2></body></html>".to_string(),
                ),
            )
                .into_response();
        }
    };

    // Compute fingerprint and whitelist
    let fingerprint = crate::cert_fingerprint(&cert_der);
    state.peer_auth.apply_decision(
        &fingerprint,
        &client_name,
        crate::net::peer_auth::AuthDecision::Whitelist,
    );
    info!(name = %client_name, fingerprint = &fingerprint[..16], "Web client enrolled and whitelisted");

    // Build PEM bundle
    let pem = match build_pem(&cert_der, &key_der) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to build PEM");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(
                    "<html><body><h2>Failed to build certificate bundle.</h2></body></html>"
                        .to_string(),
                ),
            )
                .into_response();
        }
    };

    // Return an HTML page that auto-downloads the PEM file via data: URL
    let pem_b64 = base64_encode(pem.as_bytes());
    Html(format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetFuse - Enrolled</title>
<style>
body {{ font-family: -apple-system, sans-serif; background: #f5f5f5; display: flex; justify-content: center; padding-top: 80px; }}
.card {{ background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 480px; width: 100%; }}
h2 {{ margin-bottom: 16px; color: #27ae60; }}
p {{ color: #555; margin-bottom: 12px; line-height: 1.5; }}
code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
a.btn {{ display: inline-block; padding: 10px 20px; background: #3498db; color: #fff; text-decoration: none; border-radius: 4px; margin-top: 8px; }}
a.btn:hover {{ background: #2980b9; }}
</style></head><body>
<div class="card">
<h2>Enrollment Successful</h2>
<p>Your client certificate has been generated and your browser is whitelisted.</p>
<p>Your certificate file <code>{client_name}.pem</code> should download automatically.
If not, <a class="btn" download="{client_name}.pem" href="data:application/x-pem-file;base64,{pem_b64}">Download Certificate</a></p>
<p>To use it with <code>curl</code>:</p>
<p><code>curl --cert {client_name}.pem -k https://HOST:PORT/api/ls?path=/</code></p>
</div>
<script>
var a = document.createElement('a');
a.href = 'data:application/x-pem-file;base64,{pem_b64}';
a.download = '{client_name}.pem';
document.body.appendChild(a);
a.click();
document.body.removeChild(a);
</script>
</body></html>"#
    ))
    .into_response()
}

/// Build PEM bundle containing certificate and private key.
fn build_pem(cert_der: &[u8], key_der: &[u8]) -> anyhow::Result<String> {
    use std::fmt::Write;
    let mut pem = String::new();

    // Cert PEM
    writeln!(&mut pem, "-----BEGIN CERTIFICATE-----")?;
    let b64_cert = base64_encode(cert_der);
    for chunk in b64_cert.as_bytes().chunks(64) {
        writeln!(&mut pem, "{}", std::str::from_utf8(chunk).unwrap_or(""))?;
    }
    writeln!(&mut pem, "-----END CERTIFICATE-----")?;

    // Key PEM
    writeln!(&mut pem, "-----BEGIN PRIVATE KEY-----")?;
    let b64_key = base64_encode(key_der);
    for chunk in b64_key.as_bytes().chunks(64) {
        writeln!(&mut pem, "{}", std::str::from_utf8(chunk).unwrap_or(""))?;
    }
    writeln!(&mut pem, "-----END PRIVATE KEY-----")?;

    Ok(pem)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---- Authenticated Handlers ----

async fn handle_index(State(_state): State<AppState>) -> impl IntoResponse {
    Html(WEB_UI_HTML.to_string())
}

async fn handle_ls(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> impl IntoResponse {
    let parent = normalize_file_path(&q.path);
    match state.db.list_children(&parent) {
        Ok(entries) => {
            let ls: Vec<LsEntry> = entries
                .into_iter()
                .map(|e| {
                    let trimmed = e.path.trim_end_matches('/');
                    let name = trimmed.rsplit('/').next().unwrap_or(trimmed).to_string();
                    LsEntry {
                        name,
                        kind: match e.kind {
                            EntryKind::Directory => "directory",
                            EntryKind::File => "file",
                            EntryKind::Symlink => "symlink",
                        },
                        size: e.size,
                        mtime_secs: e.mtime.secs,
                        permissions: e.permissions,
                    }
                })
                .collect();
            axum::Json(ls).into_response()
        }
        Err(e) => {
            warn!(error = %e, path = %parent, "ls failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

async fn handle_download(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> impl IntoResponse {
    let path = normalize_file_path(&q.path);
    match state.db.get_entry(&path) {
        Ok(Some(entry)) => {
            if entry.kind != EntryKind::File {
                return (StatusCode::BAD_REQUEST, "Not a file").into_response();
            }
            if let Some(hash) = &entry.hash {
                match state.store.get(hash) {
                    Ok(data) => {
                        let filename = path.rsplit('/').next().unwrap_or("download");
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/octet-stream")
                            .header(
                                header::CONTENT_DISPOSITION,
                                format!("attachment; filename=\"{filename}\""),
                            )
                            .body(Body::from(data))
                            .unwrap()
                            .into_response()
                    }
                    Err(_) => (StatusCode::NOT_FOUND, "Blob not found locally").into_response(),
                }
            } else {
                (StatusCode::NOT_FOUND, "File has no content").into_response()
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "File not found").into_response(),
        Err(e) => {
            warn!(error = %e, "download failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

async fn handle_meta(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> impl IntoResponse {
    let path = normalize_file_path(&q.path);
    match state.db.get_entry(&path) {
        Ok(Some(entry)) => {
            let meta = MetaResponse {
                path: entry.path,
                kind: match entry.kind {
                    EntryKind::Directory => "directory",
                    EntryKind::File => "file",
                    EntryKind::Symlink => "symlink",
                },
                size: entry.size,
                mtime_secs: entry.mtime.secs,
                ctime_secs: entry.ctime.secs,
                permissions: entry.permissions,
                hash: entry.hash.map(|h| hex::encode(h)),
            };
            axum::Json(meta).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => {
            warn!(error = %e, "meta failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

async fn handle_upload(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Normalize parent dir: same format FUSE uses — no trailing slash except root.
    let parent = normalize_file_path(&q.path);

    while let Ok(Some(field)) = multipart.next_field().await {
        let filename: String = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        let data: bytes::Bytes = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Failed to read upload field");
                continue;
            }
        };

        // Store blob
        let (hash, size) = match state.store.store_bytes(&data) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Failed to store blob");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Store failed").into_response();
            }
        };

        // Register blob in metadata DB
        if let Err(e) = state.db.register_blob(&hash, size, &hex::encode(hash)) {
            warn!(error = %e, "Failed to register blob");
        }

        // Build file path: "/" → "/filename", "/sub" → "/sub/filename"
        let file_path = format!("{}/{}", parent.trim_end_matches('/'), filename);
        let entry = FileEntry::new_file(file_path, parent.clone(), hash, size, state.node_id);

        if let Err(e) = state.db.upsert_entry(&entry) {
            warn!(error = %e, "Failed to upsert entry");
            return (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }

        // Emit sync event
        let _ = state.sync_tx.send(SyncEvent::FileUpdated(entry));
    }

    (StatusCode::OK, "OK").into_response()
}

async fn handle_delete(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> impl IntoResponse {
    let path = normalize_file_path(&q.path);

    match state.db.get_entry(&path) {
        Ok(Some(entry)) => {
            let mut vclock = entry.vclock.clone();
            vclock.increment(state.node_id);

            if let Err(e) = state.db.delete_entry(&path) {
                warn!(error = %e, "delete failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Delete failed").into_response();
            }

            let event = if entry.kind == EntryKind::Directory {
                SyncEvent::DirDeleted {
                    path,
                    vclock,
                    origin_node: state.node_id,
                }
            } else {
                SyncEvent::FileDeleted {
                    path,
                    vclock,
                    origin_node: state.node_id,
                }
            };
            let _ = state.sync_tx.send(event);

            (StatusCode::OK, "Deleted").into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => {
            warn!(error = %e, "delete lookup failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

async fn handle_mkdir(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> impl IntoResponse {
    // Store without trailing slash — same format FUSE uses.
    let path = normalize_file_path(&q.path);
    // Determine parent: everything before the last '/'
    let parent = match path.rsplit_once('/') {
        Some(("", _)) => "/".to_string(), // "/mydir" → parent "/"
        Some((p, _)) => p.to_string(),    // "/a/b"   → parent "/a"
        None => "/".to_string(),
    };

    let entry = FileEntry::new_dir(path.clone(), parent, state.node_id);

    if let Err(e) = state.db.upsert_entry(&entry) {
        warn!(error = %e, "mkdir failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create directory").into_response();
    }

    let _ = state.sync_tx.send(SyncEvent::DirCreated(entry));

    (StatusCode::OK, "Created").into_response()
}

/// Normalize a path to have a leading '/' and no trailing '/'.
fn normalize_file_path(path: &str) -> String {
    let mut p = path.to_string();
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Create test state with in-memory DB, temp blob store, and real PeerAuth.
    fn test_state() -> AppState {
        let node_id = Uuid::new_v4();
        let db = Arc::new(MetadataDb::open_memory(node_id).unwrap());
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(BlobStore::new(tmp.path().join("blobs")).unwrap());
        let (pending_tx, _pending_rx) = mpsc::unbounded_channel();
        let peer_auth = Arc::new(PeerAuth::new(
            tmp.path().join("peer_auth.json"),
            "test-self".to_string(),
            pending_tx,
        ));
        let (sync_tx, _sync_rx) = mpsc::unbounded_channel();
        let identity = Arc::new(
            NodeIdentity::load_or_generate(
                &tmp.path().join("cert.der"),
                &tmp.path().join("key.der"),
                "test-node",
            )
            .unwrap(),
        );

        // Leak the tempdir so it stays alive for the duration of tests
        std::mem::forget(tmp);

        Arc::new(WebServer::new(
            db, store, peer_auth, sync_tx, node_id, identity,
        ))
    }

    /// Helper to read response body as string.
    async fn body_string(resp: Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_enroll_page() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/enroll")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("NetFuse Enrollment"));
        assert!(body.contains("web_token"));
    }

    #[tokio::test]
    async fn test_enroll_submit_valid() {
        let state = test_state();

        // Step 1: Get enrollment page to generate tokens
        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/enroll")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = body_string(resp).await;

        // Extract web_token from the hidden field
        let web_token = body
            .split("name=\"web_token\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string();

        // Get console_token from the enrollment state
        let console_token = {
            let guard = state.enrollment.lock();
            guard.as_ref().unwrap().console_token.clone()
        };

        // Step 2: Submit enrollment form
        let app = build_router(state.clone());
        let form_body = format!("web_token={web_token}&console_token={console_token}");
        let req = Request::builder()
            .method("POST")
            .uri("/enroll")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Enrollment Successful"));
        assert!(body.contains(".pem"));

        // Verify the fingerprint was whitelisted in PeerAuth
        // (We can't easily extract the exact fingerprint, but we can verify the
        // enrollment state was consumed)
        assert!(state.enrollment.lock().is_none());
    }

    #[tokio::test]
    async fn test_enroll_submit_invalid_token() {
        let state = test_state();

        // Generate tokens first
        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/enroll")
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap();

        // Submit with wrong console_token
        let app = build_router(state.clone());
        let form_body = "web_token=wrong&console_token=wrong1";
        let req = Request::builder()
            .method("POST")
            .uri("/enroll")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_ls_authed() {
        let state = test_state();
        let fp = "test-fingerprint-abc123";
        state.peer_auth.apply_decision(
            fp,
            "test-client",
            crate::net::peer_auth::AuthDecision::Whitelist,
        );

        let app = build_router(state);
        let mut req = Request::builder()
            .uri("/api/ls?path=/")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        // Should return a JSON array (root dir listing, may be empty)
        assert!(body.starts_with('['));
    }

    #[tokio::test]
    async fn test_api_ls_unauthed() {
        let state = test_state();
        let app = build_router(state);

        // No ClientFingerprint extension → 403
        let req = Request::builder()
            .uri("/api/ls?path=/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // With unknown fingerprint → 403
        let state2 = test_state();
        let app2 = build_router(state2);
        let mut req2 = Request::builder()
            .uri("/api/ls?path=/")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut()
            .insert(ClientFingerprint(Some("unknown-fp".to_string())));
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_upload_and_download() {
        let state = test_state();
        let fp = "upload-test-fp";
        state.peer_auth.apply_decision(
            fp,
            "uploader",
            crate::net::peer_auth::AuthDecision::Whitelist,
        );

        // Upload a file via multipart
        let boundary = "----testboundary";
        let file_content = b"hello world from upload test";
        let multipart_body = format!(
            "------testboundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n{}\r\n------testboundary--\r\n",
            std::str::from_utf8(file_content).unwrap()
        );

        let app = build_router(state.clone());
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/upload?path=/")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(multipart_body))
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Download the file
        let app = build_router(state.clone());
        let mut req = Request::builder()
            .uri("/api/file?path=/test.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert_eq!(body, "hello world from upload test");
    }

    #[tokio::test]
    async fn test_mkdir() {
        let state = test_state();
        let fp = "mkdir-test-fp";
        state.peer_auth.apply_decision(
            fp,
            "dir-maker",
            crate::net::peer_auth::AuthDecision::Whitelist,
        );

        // Create directory
        let app = build_router(state.clone());
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/mkdir?path=/mydir")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify it appears in ls
        let app = build_router(state.clone());
        let mut req = Request::builder()
            .uri("/api/ls?path=/")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("mydir"));
    }

    #[tokio::test]
    async fn test_delete() {
        let state = test_state();
        let fp = "delete-test-fp";
        state.peer_auth.apply_decision(
            fp,
            "deleter",
            crate::net::peer_auth::AuthDecision::Whitelist,
        );

        // Upload a file first
        let boundary = "----delboundary";
        let multipart_body = "------delboundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"todelete.txt\"\r\nContent-Type: application/octet-stream\r\n\r\ndelete me\r\n------delboundary--\r\n";

        let app = build_router(state.clone());
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/upload?path=/")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(multipart_body))
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete the file
        let app = build_router(state.clone());
        let mut req = Request::builder()
            .method("DELETE")
            .uri("/api/file?path=/todelete.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify it's gone
        let app = build_router(state.clone());
        let mut req = Request::builder()
            .uri("/api/file?path=/todelete.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ClientFingerprint(Some(fp.to_string())));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
