//! Reading what services say about themselves on connections the sweep has
//! already opened: the SSH version greeting, and an HTTP `GET /` for the
//! `Server` header, login realm and page title.

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_RESPONSE: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub enum Banner {
    Ssh(String),
    Http(HttpInfo),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HttpInfo {
    pub server: Option<String>,
    /// `WWW-Authenticate` realm, which often names the product
    /// (e.g. `NETGEAR Orbi`) when the page itself is just a login prompt.
    pub realm: Option<String>,
    pub title: Option<String>,
}

/// Read a banner from a freshly connected stream, if `port` has a reader.
pub async fn grab(stream: TcpStream, ip: Ipv4Addr, port: u16) -> Option<Banner> {
    let read = async {
        match port {
            22 => ssh(stream).await.map(Banner::Ssh),
            80 => http(stream, ip).await.map(Banner::Http),
            _ => None,
        }
    };
    tokio::time::timeout(TIMEOUT, read).await.ok().flatten()
}

async fn ssh(mut stream: TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await.ok()?;
    let line = String::from_utf8_lossy(&buf[..n]);
    let line = line.lines().next()?.trim();
    line.starts_with("SSH-").then(|| clean(line, 100))
}

async fn http(stream: TcpStream, ip: Ipv4Addr) -> Option<HttpInfo> {
    let first = fetch(stream, ip, "/").await?;
    let mut info = parse_http(&first);
    // Follow one same-host plain-HTTP redirect (e.g. `/` -> `/login.html`)
    // to find a title; anything else just keeps what we have.
    if info.title.is_none()
        && let Some(path) = same_host_redirect(&first, ip)
        && let Ok(stream) = TcpStream::connect((ip, 80)).await
        && let Some(second) = fetch(stream, ip, &path).await
    {
        let next = parse_http(&second);
        info.title = next.title;
        info.realm = info.realm.or(next.realm);
        info.server = info.server.or(next.server);
    }
    (info != HttpInfo::default()).then_some(info)
}

async fn fetch(mut stream: TcpStream, ip: Ipv4Addr, path: &str) -> Option<String> {
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: giddy\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut body = Vec::new();
    // Devices often never close the connection; keep whatever arrived.
    let _ = (&mut stream).take(MAX_RESPONSE).read_to_end(&mut body).await;
    (!body.is_empty()).then(|| String::from_utf8_lossy(&body).into_owned())
}

fn split_response(resp: &str) -> (&str, &str) {
    resp.split_once("\r\n\r\n").or_else(|| resp.split_once("\n\n")).unwrap_or((resp, ""))
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim()).filter(|v| !v.is_empty())
    })
}

fn parse_http(resp: &str) -> HttpInfo {
    let (head, body) = split_response(resp);
    if !head.starts_with("HTTP/") {
        return HttpInfo::default();
    }
    let realm = header(head, "WWW-Authenticate").and_then(|v| {
        let start = v.to_ascii_lowercase().find("realm=\"")? + 7;
        let len = v[start..].find('"')?;
        Some(clean(&v[start..start + len], 80))
    });
    HttpInfo {
        server: header(head, "Server").map(|s| clean(s, 80)),
        realm: realm.filter(|r| !r.is_empty()),
        title: title(body),
    }
}

fn title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find("</title")?;
    let text = body[start..end]
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    let text = clean(&text, 80);
    (!text.is_empty()).then_some(text)
}

/// The path of a 3xx `Location` that stays on this host over plain HTTP.
fn same_host_redirect(resp: &str, ip: Ipv4Addr) -> Option<String> {
    let (head, _) = split_response(resp);
    let status = head.split_whitespace().nth(1)?;
    if !status.starts_with('3') {
        return None;
    }
    let loc = header(head, "Location")?;
    let path = if let Some(rest) = loc.strip_prefix("http://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host = authority.strip_suffix(":80").unwrap_or(authority);
        if host != ip.to_string() {
            return None;
        }
        format!("/{path}")
    } else if loc.starts_with('/') && !loc.starts_with("//") {
        loc.to_string()
    } else {
        return None;
    };
    (path != "/" && path.chars().all(|c| c.is_ascii_graphic())).then_some(path)
}

/// Collapse whitespace, drop control characters and cap the length.
fn clean(s: &str, max: usize) -> String {
    let collapsed: String =
        s.split_whitespace().collect::<Vec<_>>().join(" ").chars().filter(|c| !c.is_control()).collect();
    if collapsed.chars().count() > max { collapsed.chars().take(max - 1).chain(['…']).collect() } else { collapsed }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);

    #[test]
    fn orbi_login_prompt() {
        let resp = "HTTP/1.0 401 Unauthorized\r\nServer: uhttpd/1.0.0\r\n\
                    WWW-Authenticate: Basic realm=\"NETGEAR Orbi\"\r\n\r\n\
                    <html><head><title> 401 Authorization</title></head></html>";
        let info = parse_http(resp);
        assert_eq!(info.server.as_deref(), Some("uhttpd/1.0.0"));
        assert_eq!(info.realm.as_deref(), Some("NETGEAR Orbi"));
        assert_eq!(info.title.as_deref(), Some("401 Authorization"));
    }

    #[test]
    fn title_is_decoded_and_collapsed() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<HTML><Title lang=en>\n  Living Room &amp;\tDen </TITLE>";
        assert_eq!(parse_http(resp).title.as_deref(), Some("Living Room & Den"));
        assert_eq!(parse_http("garbage").title, None);
    }

    #[test]
    fn redirects_only_follow_same_host_http() {
        let redirect = |loc: &str| format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\n\r\n");
        assert_eq!(same_host_redirect(&redirect("/login.html"), IP).as_deref(), Some("/login.html"));
        assert_eq!(same_host_redirect(&redirect("http://10.0.0.3:80/ui/"), IP).as_deref(), Some("/ui/"));
        assert_eq!(same_host_redirect(&redirect("https://10.0.0.3/"), IP), None);
        assert_eq!(same_host_redirect(&redirect("http://example.com/x"), IP), None);
        assert_eq!(same_host_redirect(&redirect("//example.com/x"), IP), None);
        assert_eq!(same_host_redirect("HTTP/1.1 200 OK\r\nLocation: /x\r\n\r\n", IP), None);
    }

    #[test]
    fn long_text_is_truncated() {
        assert_eq!(clean("a  b\u{7}c", 10), "a bc");
        assert_eq!(clean(&"x".repeat(20), 5), "xxxx…");
    }
}
