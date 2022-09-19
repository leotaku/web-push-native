use axum::{
    body::{Bytes, Full},
    http::HeaderValue,
    response::{IntoResponse, Response},
};
use hyper::header;

#[derive(Clone, Copy, Debug)]
pub struct JavaScript<T>(pub T);

impl<T> IntoResponse for JavaScript<T>
where
    T: Into<Full<Bytes>>,
{
    fn into_response(self) -> Response {
        (
            [(header::CONTENT_TYPE, "application/javascript")],
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for JavaScript<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Json<T>(pub T);

impl<T> IntoResponse for Json<T>
where
    T: Into<Full<Bytes>>,
{
    fn into_response(self) -> Response {
        (
            [(header::CONTENT_TYPE, HeaderValue::from_static("text/json"))],
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for Json<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
