use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    BadRequest(String),
    Internal(String),
}

// lightweight error implementation without external crate
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            Self::Forbidden(msg) => write!(f, "forbidden: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::Conflict(msg) => write!(f, "conflict: {msg}"),
            Self::BadRequest(msg) => write!(f, "bad request: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg),
        };

        let body = Json(ErrorEnvelope {
            error: ErrorDetail {
                code: code.to_string(),
                message,
            },
        });

        (status, body).into_response()
    }
}
