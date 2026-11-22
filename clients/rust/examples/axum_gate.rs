//! An axum application behind TinySesam's gate in header mode.
//!
//! Run it bound to loopback behind a proxy that fulfils the duties of spec §2.1:
//!
//! ```text
//! cargo run --example axum_gate
//! ```
//!
//! A middleware turns the `Remote-*` headers into an [`Identity`] (401 without one), a route checks a role (403).
//! Responses never say why a request was refused; the log line carries only the error class.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tinysesam_gate::{HeaderMode, Identity, Requirement, authorize};

async fn gate(State(mode): State<Arc<HeaderMode>>, mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    match mode.identify(request.headers(), peer) {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(error) => {
            eprintln!("gate refused a request: {}", error.class());
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/// Plain text, so the display name needs no escaping here; in HTML it must be escaped (spec §3.2).
async fn whoami(Extension(identity): Extension<Identity>) -> String {
    format!(
        "{} ({}), id {}, {}\n",
        identity.name,
        identity.user,
        identity.id,
        identity.kind.as_str()
    )
}

async fn editors(Extension(identity): Extension<Identity>) -> Response {
    match authorize(Some(&identity), &[Requirement::Role("editors")]).status() {
        None => "editors only\n".into_response(),
        Some(status) => status.into_response(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Header mode is an explicit opt-in; the peer list refuses every client but the proxy on loopback.
    let mode = Arc::new(HeaderMode::trust_proxy().with_trusted_peers(["127.0.0.1", "::1"])?);
    let app = Router::new()
        .route("/whoami", get(whoami))
        .route("/editors", get(editors))
        .layer(middleware::from_fn_with_state(mode, gate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
