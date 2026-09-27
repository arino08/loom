//! Minimal HTTP plumbing shared by Loom's services (Warp log, witnesses,
//! Shuttle peers, the mock AUR) and clients.
//!
//! Servers are synchronous (`tiny_http`) with a small worker pool: every
//! Loom service is I/O-light and the prototype favours auditability over
//! throughput.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub remote: Option<SocketAddr>,
}

impl Request {
    pub fn q(&self, k: &str) -> Option<&str> {
        self.query.get(k).map(|s| s.as_str())
    }
    pub fn q_u64(&self, k: &str) -> Result<u64, Response> {
        self.q(k)
            .ok_or_else(|| Response::text(400, format!("missing query parameter {k}")))?
            .parse()
            .map_err(|_| Response::text(400, format!("bad integer for {k}")))
    }
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.get(&k.to_ascii_lowercase()).map(|s| s.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Response {
            status,
            content_type: "text/plain; charset=utf-8".into(),
            body: body.into().into_bytes(),
        }
    }
    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Response {
            status,
            content_type: content_type.into(),
            body,
        }
    }
    pub fn json<T: serde::Serialize>(v: &T) -> Self {
        match serde_json::to_vec_pretty(v) {
            Ok(b) => Response::bytes(200, "application/json", b),
            Err(e) => Response::text(500, e.to_string()),
        }
    }
    pub fn not_found() -> Self {
        Response::text(404, "not found")
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_query(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(kv), String::new()),
        })
        .collect()
}

pub struct Server {
    pub addr: SocketAddr,
    inner: Arc<tiny_http::Server>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Server {
    /// Bind and start serving on `threads` workers. `addr` may use port 0.
    pub fn start(addr: &str, threads: usize, handler: Handler) -> anyhow::Result<Server> {
        let inner = Arc::new(
            tiny_http::Server::http(addr).map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?,
        );
        let bound = inner
            .server_addr()
            .to_ip()
            .ok_or_else(|| anyhow::anyhow!("not an IP listener"))?;
        let mut hs = vec![];
        for _ in 0..threads.max(1) {
            let srv = inner.clone();
            let h = handler.clone();
            hs.push(std::thread::spawn(move || {
                while let Ok(mut rq) = srv.recv() {
                    let full = rq.url().to_string();
                    let (path, query) = match full.split_once('?') {
                        Some((p, q)) => (p.to_string(), parse_query(q)),
                        None => (full.clone(), BTreeMap::new()),
                    };
                    let mut body = vec![];
                    let _ = rq.as_reader().take(64 << 20).read_to_end(&mut body);
                    let headers = rq
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.as_str().as_str().to_ascii_lowercase(),
                                h.value.as_str().to_string(),
                            )
                        })
                        .collect();
                    let req = Request {
                        method: rq.method().as_str().to_string(),
                        path,
                        query,
                        headers,
                        body,
                        remote: rq.remote_addr().copied(),
                    };
                    let resp = h(&req);
                    let ct = tiny_http::Header::from_bytes("Content-Type", resp.content_type.as_bytes())
                        .expect("valid header");
                    let _ = rq.respond(
                        tiny_http::Response::from_data(resp.body)
                            .with_status_code(resp.status)
                            .with_header(ct),
                    );
                }
            }));
        }
        Ok(Server {
            addr: bound,
            inner,
            threads: hs,
        })
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn shutdown(self) {
        self.inner.unblock();
        for _ in 0..self.threads.len() {
            self.inner.unblock();
        }
        for t in self.threads {
            let _ = t.join();
        }
    }

    /// Block forever (for daemons).
    pub fn wait(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------- client

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// Could not reach the server at all (connection refused, timeout, DNS).
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// Server answered with a non-2xx status.
    #[error("HTTP {status}: {body}")]
    Status { status: u16, body: String },
}

fn is_loopback(url: &str) -> bool {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', ':']).next().unwrap_or("");
    host == "localhost" || host.starts_with("127.") || host == "[::1]"
}

/// HTTP client. Honours `HTTPS_PROXY`/`HTTP_PROXY` for non-loopback hosts
/// only (loopback testbeds must never be routed through a proxy).
#[derive(Clone)]
pub struct Client {
    direct: ureq::Agent,
    proxied: ureq::Agent,
    pub headers: Vec<(String, String)>,
}

impl Client {
    pub fn new(timeout: Duration) -> Self {
        let direct = ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout(timeout.max(Duration::from_secs(30)))
            .build();
        let proxied = ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout(timeout.max(Duration::from_secs(30)))
            .try_proxy_from_env(true)
            .build();
        Client {
            direct,
            proxied,
            headers: vec![],
        }
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    fn agent(&self, url: &str) -> &ureq::Agent {
        if is_loopback(url) {
            &self.direct
        } else {
            &self.proxied
        }
    }

    fn finish(r: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, HttpError> {
        match r {
            Ok(resp) => {
                let mut buf = vec![];
                resp.into_reader()
                    .take(512 << 20)
                    .read_to_end(&mut buf)
                    .map_err(|e| HttpError::Unavailable(e.to_string()))?;
                Ok(buf)
            }
            Err(ureq::Error::Status(status, resp)) => Err(HttpError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(ureq::Error::Transport(t)) => Err(HttpError::Unavailable(t.to_string())),
        }
    }

    pub fn get(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        let mut req = self.agent(url).get(url);
        for (k, v) in &self.headers {
            req = req.set(k, v);
        }
        Self::finish(req.call())
    }

    pub fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let b = self.get(url)?;
        Ok(serde_json::from_slice(&b)?)
    }

    pub fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        let mut req = self.agent(url).post(url).set("Content-Type", content_type);
        for (k, v) in &self.headers {
            req = req.set(k, v);
        }
        Self::finish(req.send_bytes(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing() {
        let q = parse_query("arg[]=a%2Bb&x=1+2&flag");
        assert_eq!(q["arg[]"], "a+b");
        assert_eq!(q["x"], "1 2");
        assert_eq!(q["flag"], "");
    }

    #[test]
    fn roundtrip_server() {
        let h: Handler = Arc::new(|r: &Request| {
            Response::text(200, format!("{} {} {}", r.method, r.path, r.q("a").unwrap_or("")))
        });
        let s = Server::start("127.0.0.1:0", 2, h).unwrap();
        let c = Client::new(Duration::from_secs(2));
        let body = c.get(&format!("{}/x?a=1", s.url())).unwrap();
        assert_eq!(body, b"GET /x 1");
        s.shutdown();
    }
}
