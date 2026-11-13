use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub db_path: String,
    pub log_level: String,
}

impl Config {
    pub fn from_env() -> Self {
        let host = env::var("KEPCHUK_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("KEPCHUK_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let db_path = env::var("KEPCHUK_DB_PATH").unwrap_or_else(|_| "kepchuk.db".to_string());
        let log_level = env::var("KEPCHUK_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

        Self {
            host,
            port,
            db_path,
            log_level,
        }
    }
}
