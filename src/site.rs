//! Built-in static site used for non-XHTTP traffic.
//!
//! This keeps the origin useful as a normal content endpoint while the XHTTP
//! mount remains a strict protocol surface.

use http::{Method, StatusCode};

pub struct StaticReply {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub body: &'static [u8],
    pub cache_control: &'static str,
    pub etag: &'static str,
    pub allow: Option<&'static str>,
}

const LAST_MODIFIED: &str = "Tue, 16 Jun 2026 08:00:00 GMT";
const CACHE_HTML: &str = "public, max-age=300";
const CACHE_ASSET: &str = "public, max-age=86400";

pub fn last_modified() -> &'static str {
    LAST_MODIFIED
}

pub fn resolve(method: &Method, path: &str) -> StaticReply {
    if method != Method::GET && method != Method::HEAD {
        return StaticReply {
            status: StatusCode::METHOD_NOT_ALLOWED,
            content_type: "text/html; charset=utf-8",
            body: METHOD_NOT_ALLOWED_HTML,
            cache_control: "no-store",
            etag: "\"68513c00-0195\"",
            allow: Some("GET, HEAD"),
        };
    }

    match canonical_path(path) {
        "/" | "/index.html" => html(StatusCode::OK, INDEX_HTML, "\"68513c00-2f49\""),
        "/about/" | "/about" => html(StatusCode::OK, ABOUT_HTML, "\"68513c00-16bc\""),
        "/posts/cloud-edge-routing/" | "/posts/cloud-edge-routing" => {
            html(StatusCode::OK, POST_EDGE_HTML, "\"68513c00-20d7\"")
        }
        "/posts/http2-origin-notes/" | "/posts/http2-origin-notes" => {
            html(StatusCode::OK, POST_H2_HTML, "\"68513c00-1e7a\"")
        }
        "/posts/tls-session-resumption/" | "/posts/tls-session-resumption" => {
            html(StatusCode::OK, POST_TLS_HTML, "\"68513c00-1d5f\"")
        }
        "/assets/site.css" => StaticReply {
            status: StatusCode::OK,
            content_type: "text/css; charset=utf-8",
            body: SITE_CSS,
            cache_control: CACHE_ASSET,
            etag: "\"68513c00-0a11\"",
            allow: None,
        },
        "/favicon.svg" | "/favicon.ico" => StaticReply {
            status: StatusCode::OK,
            content_type: "image/svg+xml",
            body: FAVICON_SVG,
            cache_control: CACHE_ASSET,
            etag: "\"68513c00-0132\"",
            allow: None,
        },
        "/robots.txt" => StaticReply {
            status: StatusCode::OK,
            content_type: "text/plain; charset=utf-8",
            body: ROBOTS_TXT,
            cache_control: CACHE_HTML,
            etag: "\"68513c00-002f\"",
            allow: None,
        },
        "/sitemap.xml" => StaticReply {
            status: StatusCode::OK,
            content_type: "application/xml; charset=utf-8",
            body: SITEMAP_XML,
            cache_control: CACHE_HTML,
            etag: "\"68513c00-02d4\"",
            allow: None,
        },
        _ => html(StatusCode::NOT_FOUND, NOT_FOUND_HTML, "\"68513c00-0320\""),
    }
}

fn canonical_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn html(status: StatusCode, body: &'static [u8], etag: &'static str) -> StaticReply {
    StaticReply {
        status,
        content_type: "text/html; charset=utf-8",
        body,
        cache_control: CACHE_HTML,
        etag,
        allow: None,
    }
}

const INDEX_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Edge Notes</title>
  <meta name="description" content="Field notes on HTTP delivery, origin design, and practical edge operations.">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <header class="site-header">
    <a class="brand" href="/">Edge Notes</a>
    <nav aria-label="Primary">
      <a href="/about/">About</a>
      <a href="/posts/cloud-edge-routing/">Routing</a>
      <a href="/posts/http2-origin-notes/">HTTP/2</a>
    </nav>
  </header>
  <main>
    <section class="intro">
      <p class="eyebrow">Operations journal</p>
      <h1>Reliable web delivery starts with boring origin behavior.</h1>
      <p>Short essays and checklists for running static sites, reverse proxies, and edge caches without surprising clients or operators.</p>
    </section>
    <section class="post-list" aria-label="Recent posts">
      <article>
        <p class="date">June 16, 2026</p>
        <h2><a href="/posts/cloud-edge-routing/">Routing requests through an edge cache</a></h2>
        <p>How cache keys, origin health, and request headers interact when a CDN sits in front of a small origin service.</p>
      </article>
      <article>
        <p class="date">June 12, 2026</p>
        <h2><a href="/posts/http2-origin-notes/">HTTP/2 origin notes for small services</a></h2>
        <p>Practical defaults for long lived responses, stream concurrency, and proxy buffering when the edge speaks HTTP/2 upstream.</p>
      </article>
      <article>
        <p class="date">June 03, 2026</p>
        <h2><a href="/posts/tls-session-resumption/">TLS session resumption and cache locality</a></h2>
        <p>A plain-language look at connection reuse, session tickets, and why clean termination boundaries matter.</p>
      </article>
    </section>
  </main>
  <footer>
    <p>Edge Notes publishes implementation notes for quiet, dependable web infrastructure.</p>
  </footer>
</body>
</html>
"#;

const ABOUT_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>About - Edge Notes</title>
  <meta name="description" content="About Edge Notes, an operations journal for practical web delivery.">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <header class="site-header">
    <a class="brand" href="/">Edge Notes</a>
    <nav aria-label="Primary"><a href="/about/">About</a><a href="/posts/cloud-edge-routing/">Routing</a><a href="/posts/http2-origin-notes/">HTTP/2</a></nav>
  </header>
  <main class="article">
    <p class="eyebrow">About</p>
    <h1>Notes from the practical edge of web operations.</h1>
    <p>Edge Notes is a small static publication about HTTP services, deployment hygiene, cache behavior, and observability. The writing favors repeatable checks over novelty and assumes that predictable defaults are a feature.</p>
    <p>The site is intentionally simple: cacheable documents, stable links, modest assets, and markup that remains useful without client-side JavaScript.</p>
  </main>
  <footer><p><a href="/">Back to the index</a></p></footer>
</body>
</html>
"#;

const POST_EDGE_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Routing requests through an edge cache - Edge Notes</title>
  <meta name="description" content="A field note on cache keys, origin health, and CDN request routing.">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <header class="site-header"><a class="brand" href="/">Edge Notes</a><nav aria-label="Primary"><a href="/about/">About</a><a href="/posts/cloud-edge-routing/">Routing</a><a href="/posts/http2-origin-notes/">HTTP/2</a></nav></header>
  <main class="article">
    <p class="date">June 16, 2026</p>
    <h1>Routing requests through an edge cache</h1>
    <p>A CDN changes the shape of production traffic. The origin no longer sees every client directly, and the cache becomes part of the application contract.</p>
    <h2>Keep the cache key readable</h2>
    <p>Start with the path, host, method, and only the query parameters that change the representation. Headers should enter the key deliberately, because accidental variation turns a cache into a pass-through proxy.</p>
    <h2>Make health checks boring</h2>
    <p>Health endpoints should avoid dependencies that are not required to serve cached documents. A small response, explicit status code, and predictable timeout make automated routing decisions easier to reason about.</p>
    <h2>Plan for origin pressure</h2>
    <p>Cache misses arrive in bursts after deploys, purges, and regional failover. Origin limits should reject excess work early and consistently while preserving useful telemetry for the operator.</p>
  </main>
  <footer><p><a href="/">Back to the index</a></p></footer>
</body>
</html>
"#;

const POST_H2_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HTTP/2 origin notes for small services - Edge Notes</title>
  <meta name="description" content="HTTP/2 origin defaults for services behind a CDN or reverse proxy.">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <header class="site-header"><a class="brand" href="/">Edge Notes</a><nav aria-label="Primary"><a href="/about/">About</a><a href="/posts/cloud-edge-routing/">Routing</a><a href="/posts/http2-origin-notes/">HTTP/2</a></nav></header>
  <main class="article">
    <p class="date">June 12, 2026</p>
    <h1>HTTP/2 origin notes for small services</h1>
    <p>HTTP/2 is most useful at the origin when it removes connection churn without hiding backpressure. The protocol gives many streams one connection, but the service still needs firm memory and lifetime limits.</p>
    <h2>Disable proxy buffering for streams</h2>
    <p>Long-lived responses need explicit buffering policy at each hop. Otherwise the edge or reverse proxy can collect data in memory and delay delivery in ways that are hard to diagnose from the client side.</p>
    <h2>Bound request bodies</h2>
    <p>Small services should reject oversized uploads before they allocate large buffers. Size hints help when present, but streaming accounting is still required because not every client sends a reliable length.</p>
    <h2>Keep fallbacks static</h2>
    <p>A static fallback page is cheap to serve, easy to cache, and still useful during partial outages. It also keeps probes and human checks from depending on application state.</p>
  </main>
  <footer><p><a href="/">Back to the index</a></p></footer>
</body>
</html>
"#;

const POST_TLS_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TLS session resumption and cache locality - Edge Notes</title>
  <meta name="description" content="A short note on TLS resumption, connection reuse, and termination boundaries.">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <header class="site-header"><a class="brand" href="/">Edge Notes</a><nav aria-label="Primary"><a href="/about/">About</a><a href="/posts/cloud-edge-routing/">Routing</a><a href="/posts/http2-origin-notes/">HTTP/2</a></nav></header>
  <main class="article">
    <p class="date">June 03, 2026</p>
    <h1>TLS session resumption and cache locality</h1>
    <p>TLS resumption is a latency feature, not a substitute for capacity planning. It helps most when clients return to the same termination layer and the edge can reuse existing upstream connections.</p>
    <h2>Separate public and origin termination</h2>
    <p>When a CDN terminates public TLS, the origin profile is an internal contract between the edge and the service. That boundary should be documented so packet captures and metrics are interpreted correctly.</p>
    <h2>Measure the visible path</h2>
    <p>Operators should test both the client-to-edge leg and the edge-to-origin leg. A healthy origin trace does not prove that public clients see the same handshake, protocol, or congestion behavior.</p>
  </main>
  <footer><p><a href="/">Back to the index</a></p></footer>
</body>
</html>
"#;

const NOT_FOUND_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Page not found - Edge Notes</title>
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <main class="article">
    <p class="eyebrow">404</p>
    <h1>Page not found</h1>
    <p>The requested page is not available. The latest notes are listed on the home page.</p>
    <p><a href="/">Return to the index</a></p>
  </main>
</body>
</html>
"#;

const METHOD_NOT_ALLOWED_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Method not allowed - Edge Notes</title></head>
<body><h1>Method not allowed</h1><p>This resource accepts GET and HEAD requests.</p></body>
</html>
"#;

const SITE_CSS: &[u8] = br#"html{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1f2933;background:#fbfbf8}body{margin:0}.site-header{max-width:920px;margin:0 auto;padding:28px 20px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #e5e2d9}.brand{font-weight:700;color:#111827;text-decoration:none}nav{display:flex;gap:18px}a{color:#24527a;text-decoration:none}a:hover{text-decoration:underline}main{max-width:920px;margin:0 auto;padding:42px 20px}.intro{max-width:760px}.eyebrow,.date{color:#667085;font-size:14px;letter-spacing:.04em;text-transform:uppercase}h1{font-size:42px;line-height:1.12;margin:10px 0 18px;color:#111827}h2{font-size:23px;margin:0 0 8px}.intro p,.article p{font-size:18px;line-height:1.72;color:#344054}.post-list{display:grid;gap:22px;margin-top:34px}.post-list article{padding:22px 0;border-top:1px solid #e5e2d9}.article{max-width:760px}.article h2{margin-top:30px}footer{max-width:920px;margin:0 auto;padding:26px 20px 42px;color:#667085;border-top:1px solid #e5e2d9}@media(max-width:640px){.site-header{align-items:flex-start;gap:14px;flex-direction:column}nav{flex-wrap:wrap}h1{font-size:32px}.intro p,.article p{font-size:16px}}"#;

const FAVICON_SVG: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#24527a"/><path d="M16 18h32v6H16zm0 11h24v6H16zm0 11h32v6H16z" fill="#fbfbf8"/></svg>"##;

const ROBOTS_TXT: &[u8] = b"User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n";

const SITEMAP_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/about/</loc></url>
  <url><loc>/posts/cloud-edge-routing/</loc></url>
  <url><loc>/posts/http2-origin-notes/</loc></url>
  <url><loc>/posts/tls-session-resumption/</loc></url>
</urlset>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_index_and_assets() {
        let index = resolve(&Method::GET, "/");
        assert_eq!(index.status, StatusCode::OK);
        assert!(index.body.windows(10).any(|w| w == b"Edge Notes"));

        let css = resolve(&Method::GET, "/assets/site.css");
        assert_eq!(css.status, StatusCode::OK);
        assert_eq!(css.content_type, "text/css; charset=utf-8");
        assert_eq!(css.cache_control, CACHE_ASSET);
    }

    #[test]
    fn unknown_get_is_static_404() {
        let reply = resolve(&Method::GET, "/missing");
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn rejects_non_read_methods_like_static_site() {
        let reply = resolve(&Method::POST, "/");
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(reply.allow, Some("GET, HEAD"));
    }
}
