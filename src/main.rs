use kepchuk::api::create_router;
use kepchuk::api::middleware::AppState;
use kepchuk::config::Config;
use kepchuk::nonce::memory::MemoryNonceStore;
use kepchuk::storage::sqlite::SqliteStorage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();

    // initialize tracing subscriber
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level)),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!(
        host = %config.host,
        port = %config.port,
        db_path = %config.db_path,
        "initializing kepchuk api server"
    );

    // initialize persistent sqlite storage and in-memory nonce store
    let storage = SqliteStorage::new(&config.db_path)?;
    let nonce = MemoryNonceStore::new();

    let state = AppState {
        storage: Arc::new(storage),
        nonce: Arc::new(nonce),
    };

    let app = create_router(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("listening on http://{}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("server shutdown cleanly");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install ctrl+c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received ctrl+c signal");
        },
        _ = terminate => {
            info!("received terminate signal");
        },
    }
}
