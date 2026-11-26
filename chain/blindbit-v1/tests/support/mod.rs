//! Minimal std-only HTTP/1.1 mock server for blindbit client/backend tests.
// Helper items are consumed by different test targets.
#![allow(dead_code)]
//!
//! One thread per connection; every response carries `Connection: close`.
//! Each request's target line (path + query) is recorded for assertions.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// How a matched route answers.
pub enum Route {
    /// Always answer with this status + body.
    Static(u16, String),
    /// Answer 400 `{"error":"Server does not allow dustLimits"}` when the
    /// request target carries a `dustLimit=` query, otherwise 200 with the
    /// given body. Mirrors the blindbit-regtest build on the rig.
    DustLimitRejected(String),
}

#[derive(Clone, Default)]
pub struct Recording {
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl Recording {
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// Binds 127.0.0.1:0, spawns the accept loop, returns the recording handle
/// and the bound port. Routes are matched by path prefix, first match wins.
pub fn spawn(routes: Vec<(&'static str, Route)>) -> (Recording, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().unwrap().port();
    let recording = Recording {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let routes: Arc<Vec<(String, Route)>> = Arc::new(
        routes
            .into_iter()
            .map(|(prefix, route)| (prefix.to_owned(), route))
            .collect(),
    );
    let state = recording.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let state = state.clone();
            let routes = routes.clone();
            std::thread::spawn(move || handle(stream, state, routes));
        }
    });
    (recording, port)
}

fn handle(mut stream: TcpStream, state: Recording, routes: Arc<Vec<(String, Route)>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(n) if n == 0 => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first_line = text.lines().next().unwrap_or("");
    let target = first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    state.requests.lock().unwrap().push(target.clone());

    let path = target.split('?').next().unwrap_or("/");
    let route = routes
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix.as_str()));
    let (status, body) = match route {
        Some((_, Route::Static(status, body))) => (*status, body.clone()),
        Some((_, Route::DustLimitRejected(ok_body))) => {
            if target.contains("dustLimit=") {
                (
                    400,
                    "{\"error\":\"Server does not allow dustLimits\"}".to_owned(),
                )
            } else {
                (200, ok_body.clone())
            }
        }
        None => (404, "{\"error\":\"not found\"}".to_owned()),
    };
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}
