//! The HTTP transport abstraction and its implementations.
//!
//! [`HttpClient`] is deliberately tiny (a GET and a JSON POST) and
//! object-safe, so feed clients take `&dyn HttpClient` and tests inject a
//! stub. All calls are outbound, from the end user's machine to public
//! endpoints; there is no vendor-hosted server or proxy.

use anyhow::Result;

/// A minimal HTTP response: the status code and the body as a string.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl HttpResponse {
    /// Whether the status is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// An outbound HTTP client. Non-2xx responses (e.g. a 404 for a missing
/// package) are returned as `Ok(HttpResponse)` with the status preserved, so
/// callers can treat them as signals rather than errors. Only transport-level
/// failures (DNS, TLS, timeout) return `Err`.
pub trait HttpClient {
    /// Perform a GET request.
    fn get(&self, url: &str) -> Result<HttpResponse>;

    /// Perform a POST request with the given content type and body bytes.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpResponse>;
}

/// Forward through a shared reference, so `&C` is also an `HttpClient`. This
/// lets a caller wrap a client while keeping its own handle (for example, a
/// test that inspects the wrapped mock after caching).
impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn get(&self, url: &str) -> Result<HttpResponse> {
        (**self).get(url)
    }

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpResponse> {
        (**self).post(url, content_type, body)
    }
}

pub use caching::CachingHttpClient;

mod caching {
    use super::{HttpClient, HttpResponse};
    use anyhow::{Context, Result};
    use std::hash::{Hash, Hasher};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    /// Wraps any [`HttpClient`] with an on-disk response cache, so repeated
    /// lookups (and re-runs) reuse a fresh response instead of re-querying.
    /// This is the "query-live-and-cache from the user's machine" model: the
    /// cache is local to the user, never a shared server-side mirror.
    pub struct CachingHttpClient<H: HttpClient> {
        inner: H,
        dir: PathBuf,
        ttl: Duration,
    }

    impl<H: HttpClient> CachingHttpClient<H> {
        /// Cache under the user's cache directory with entries valid for `ttl`.
        pub fn new(inner: H, ttl: Duration) -> Result<Self> {
            Self::with_dir(inner, default_cache_dir(), ttl)
        }

        /// Cache in a specific directory (used by tests).
        pub fn with_dir(inner: H, dir: PathBuf, ttl: Duration) -> Result<Self> {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating cache directory {}", dir.display()))?;
            Ok(Self { inner, dir, ttl })
        }

        fn path_for(&self, ident: &str) -> PathBuf {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            ident.hash(&mut hasher);
            self.dir.join(format!("{:016x}", hasher.finish()))
        }

        fn read(&self, ident: &str) -> Option<HttpResponse> {
            let path = self.path_for(ident);
            let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
            if !is_fresh(SystemTime::now(), modified, self.ttl) {
                return None; // stale, or future-dated from clock skew
            }
            let contents = std::fs::read_to_string(&path).ok()?;
            // Format: line 1 = identity, line 2 = status, remainder = body.
            let mut parts = contents.splitn(3, '\n');
            if parts.next()? != ident {
                return None; // hash collision guard
            }
            let status: u16 = parts.next()?.parse().ok()?;
            let body = parts.next().unwrap_or("").to_string();
            Some(HttpResponse { status, body })
        }

        fn write(&self, ident: &str, resp: &HttpResponse) {
            // Cache only stable results (2xx and 404); writes are best-effort.
            if resp.is_success() || resp.status == 404 {
                let contents = format!("{ident}\n{}\n{}", resp.status, resp.body);
                let _ = std::fs::write(self.path_for(ident), contents);
            }
        }
    }

    impl<H: HttpClient> HttpClient for CachingHttpClient<H> {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            let ident = request_ident("GET", url, b"");
            if let Some(hit) = self.read(&ident) {
                return Ok(hit);
            }
            let resp = self.inner.get(url)?;
            self.write(&ident, &resp);
            Ok(resp)
        }

        fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpResponse> {
            let ident = request_ident("POST", url, body);
            if let Some(hit) = self.read(&ident) {
                return Ok(hit);
            }
            let resp = self.inner.post(url, content_type, body)?;
            self.write(&ident, &resp);
            Ok(resp)
        }
    }

    /// Whether a cache entry with the given `modified` time is still fresh. A
    /// future-dated `modified` (clock moved backwards, restored backup, skewed
    /// machine) is treated as stale, so uncertainty never serves an old
    /// response past its lifetime.
    fn is_fresh(now: SystemTime, modified: SystemTime, ttl: Duration) -> bool {
        match now.duration_since(modified) {
            Ok(age) => age <= ttl,
            Err(_) => false,
        }
    }

    /// A newline-free identity for a request: method, url, and a hash of the
    /// body (so distinct POST queries to the same URL key separately).
    fn request_ident(method: &str, url: &str, body: &[u8]) -> String {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        body.hash(&mut hasher);
        format!("{method} {url} {:016x}", hasher.finish())
    }

    fn default_cache_dir() -> PathBuf {
        for var in ["XDG_CACHE_HOME", "HOME"] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() {
                    let base = PathBuf::from(value);
                    let base = if var == "HOME" {
                        base.join(".cache")
                    } else {
                        base
                    };
                    return base.join("vulkro-live");
                }
            }
        }
        std::env::temp_dir().join("vulkro-live-cache")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::http::MockHttp;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        fn temp_dir() -> PathBuf {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!("vulkro-cache-test-{}-{n}", std::process::id()))
        }

        #[test]
        fn second_get_is_served_from_cache() {
            let mock = MockHttp::new().on_get("example.com/pkg", 200, "hello");
            let cache =
                CachingHttpClient::with_dir(&mock, temp_dir(), Duration::from_secs(3600)).unwrap();
            assert_eq!(cache.get("https://example.com/pkg").unwrap().body, "hello");
            assert_eq!(cache.get("https://example.com/pkg").unwrap().body, "hello");
            // The inner mock was queried exactly once; the second read hit disk.
            assert_eq!(mock.calls().len(), 1);
        }

        #[test]
        fn freshness_treats_future_dated_entries_as_stale() {
            let ttl = Duration::from_secs(3600);
            let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
            // Recently written: fresh.
            assert!(is_fresh(base, base - Duration::from_secs(10), ttl));
            // Older than the TTL: stale.
            assert!(!is_fresh(base, base - Duration::from_secs(7200), ttl));
            // Future-dated (clock skew): stale, not fresh-forever.
            assert!(!is_fresh(base, base + Duration::from_secs(3600), ttl));
        }

        #[test]
        fn distinct_post_bodies_cache_separately() {
            let mock = MockHttp::new()
                .on_post("api", Some("alpha"), 200, r#"{"a":1}"#)
                .on_post("api", Some("beta"), 200, r#"{"b":2}"#);
            let cache =
                CachingHttpClient::with_dir(&mock, temp_dir(), Duration::from_secs(3600)).unwrap();
            assert_eq!(
                cache
                    .post("https://api", "application/json", b"alpha")
                    .unwrap()
                    .body,
                r#"{"a":1}"#
            );
            assert_eq!(
                cache
                    .post("https://api", "application/json", b"beta")
                    .unwrap()
                    .body,
                r#"{"b":2}"#
            );
        }
    }
}

#[cfg(feature = "net")]
pub use net::UreqClient;

#[cfg(feature = "net")]
mod net {
    use super::{HttpClient, HttpResponse};
    use anyhow::{bail, Context, Result};
    use std::io::Read;
    use std::time::Duration;

    /// Cap on the response body we read into memory. This is far above the
    /// largest npm packument (popular packages such as typescript and
    /// react-native are around 15 MiB), yet bounded so a runaway response
    /// cannot exhaust memory. We read the body ourselves because ureq's
    /// `into_string` caps at 10 MiB, which is too small for those packages and
    /// would turn a normal lookup into a hard error.
    const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

    /// The real HTTP client, backed by a small blocking `ureq` agent.
    pub struct UreqClient {
        agent: ureq::Agent,
    }

    impl UreqClient {
        /// Build a client with sensible timeouts and a descriptive user agent.
        pub fn new() -> Self {
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .user_agent(concat!(
                    "vulkro-live/",
                    env!("CARGO_PKG_VERSION"),
                    " (+https://vulkro.com)"
                ))
                .build();
            Self { agent }
        }
    }

    impl Default for UreqClient {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Read a response body into a `String`, bounded to `max_bytes` so an
    /// unexpectedly huge response fails cleanly rather than exhausting memory,
    /// while still accepting bodies larger than ureq's own 10 MiB
    /// `into_string` limit.
    fn read_body_limited(reader: impl Read, max_bytes: usize) -> Result<String> {
        let mut buf = Vec::new();
        reader
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut buf)
            .context("reading HTTP response body")?;
        if buf.len() > max_bytes {
            bail!(
                "HTTP response body exceeded the {max_bytes}-byte limit; this is \
                 unexpected for a package lookup, please report it"
            );
        }
        String::from_utf8(buf).context("HTTP response body was not valid UTF-8")
    }

    fn into_response(resp: ureq::Response) -> Result<HttpResponse> {
        let status = resp.status();
        let body = read_body_limited(resp.into_reader(), MAX_BODY_BYTES)?;
        Ok(HttpResponse { status, body })
    }

    fn map_error(url: &str, err: ureq::Error) -> Result<HttpResponse> {
        match err {
            // A non-2xx status is a normal signal for us (e.g. npm 404 =
            // missing), so surface it as an Ok response, not an error.
            ureq::Error::Status(code, resp) => {
                let body =
                    read_body_limited(resp.into_reader(), MAX_BODY_BYTES).unwrap_or_default();
                Ok(HttpResponse { status: code, body })
            }
            ureq::Error::Transport(transport) => {
                Err(anyhow::Error::new(transport)
                    .context(format!("network request to {url} failed")))
            }
        }
    }

    impl HttpClient for UreqClient {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            match self.agent.get(url).call() {
                Ok(resp) => into_response(resp),
                Err(err) => map_error(url, err),
            }
        }

        fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpResponse> {
            match self
                .agent
                .post(url)
                .set("Content-Type", content_type)
                .send_bytes(body)
            {
                Ok(resp) => into_response(resp),
                Err(err) => map_error(url, err),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::read_body_limited;
        use std::io::Cursor;

        #[test]
        fn reads_body_under_the_limit() {
            let body = read_body_limited(Cursor::new(b"hello".to_vec()), 1024).unwrap();
            assert_eq!(body, "hello");
        }

        #[test]
        fn reads_body_at_exactly_the_limit() {
            let body = read_body_limited(Cursor::new(vec![b'x'; 10]), 10).unwrap();
            assert_eq!(body.len(), 10);
        }

        #[test]
        fn errors_instead_of_truncating_when_over_the_limit() {
            // Regression: ureq's into_string() capped bodies at 10 MiB, turning
            // large-but-valid packuments (typescript, react-native) into hard
            // errors. We now accept up to a much larger cap and, beyond it,
            // return a clear error rather than silently truncating into
            // invalid JSON.
            let err = read_body_limited(Cursor::new(vec![b'x'; 100]), 10).unwrap_err();
            assert!(err.to_string().contains("exceeded"));
        }
    }
}

#[cfg(any(test, feature = "testing"))]
pub use testing::MockHttp;

#[cfg(any(test, feature = "testing"))]
mod testing {
    use super::{HttpClient, HttpResponse};
    use anyhow::{bail, Result};
    use std::sync::Mutex;

    struct Route {
        method: &'static str,
        url_contains: String,
        body_contains: Option<String>,
        response: HttpResponse,
    }

    /// An in-memory HTTP stub for tests, with no network access.
    ///
    /// Routes are matched by method plus a URL substring (and, for POSTs, an
    /// optional body substring, which lets a single test distinguish two OSV
    /// queries that share a URL). Any unmatched request returns an error so a
    /// test fails loudly when it forgets to stub a call, or when the code
    /// makes a request it should have skipped.
    #[derive(Default)]
    pub struct MockHttp {
        routes: Vec<Route>,
        calls: Mutex<Vec<String>>,
    }

    impl MockHttp {
        pub fn new() -> Self {
            Self::default()
        }

        /// Stub a GET whose URL contains `url_contains`.
        #[must_use]
        pub fn on_get(mut self, url_contains: &str, status: u16, body: &str) -> Self {
            self.routes.push(Route {
                method: "GET",
                url_contains: url_contains.to_string(),
                body_contains: None,
                response: HttpResponse {
                    status,
                    body: body.to_string(),
                },
            });
            self
        }

        /// Stub a POST whose URL contains `url_contains` and (optionally) whose
        /// request body contains `body_contains`.
        #[must_use]
        pub fn on_post(
            mut self,
            url_contains: &str,
            body_contains: Option<&str>,
            status: u16,
            body: &str,
        ) -> Self {
            self.routes.push(Route {
                method: "POST",
                url_contains: url_contains.to_string(),
                body_contains: body_contains.map(str::to_string),
                response: HttpResponse {
                    status,
                    body: body.to_string(),
                },
            });
            self
        }

        /// The requests this mock has served, as `"METHOD url"` strings.
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }

        fn respond(
            &self,
            method: &'static str,
            url: &str,
            body: Option<&str>,
        ) -> Result<HttpResponse> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(format!("{method} {url}"));
            }
            for route in &self.routes {
                if route.method != method || !url.contains(&route.url_contains) {
                    continue;
                }
                if let Some(needle) = &route.body_contains {
                    match body {
                        Some(b) if b.contains(needle) => {}
                        _ => continue,
                    }
                }
                return Ok(route.response.clone());
            }
            bail!("MockHttp: no stub matched {method} {url}")
        }
    }

    impl HttpClient for MockHttp {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            self.respond("GET", url, None)
        }

        fn post(&self, url: &str, _content_type: &str, body: &[u8]) -> Result<HttpResponse> {
            let body = String::from_utf8_lossy(body).into_owned();
            self.respond("POST", url, Some(&body))
        }
    }
}
