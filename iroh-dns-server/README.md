# iroh-dns-server

A server that functions as a [pkarr](https://github.com/Nuhvi/pkarr/) relay and
[DNS](https://de.wikipedia.org/wiki/Domain_Name_System) server.

This server compiles to a binary `iroh-dns-server`. It needs a config file, of
which there are two examples included:

- [`config.dev.toml`](./config.dev.toml) - suitable for local development
- [`config.prod.toml`](./config.prod.toml) - suitable for production, after
  adjusting the domain names and IP addresses

The server will expose the following services:

- A DNS server listening on UDP and TCP for DNS queries
- A HTTP and/or HTTPS server which provides the following routes:
  - `/pkarr`: `GET` and `PUT` for pkarr signed packets
  - `/dns-query`: Answer DNS queries over
    [DNS-over-HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)

All received and valid pkarr signed packets will be served over DNS. The pkarr
packet origin will be appended with the origin as configured by this server.

## Resource limits

The optional `[limits]` table bounds process-owned ingress work. Omitting it uses
finite production defaults: 1,024 concurrent UDP requests, 256 DNS TCP
connections, 512 combined HTTP/HTTPS connections, 1,024 in-flight HTTP requests,
and 32 HTTP/2 streams per connection. New HTTP connections are limited to 200 per
second with a burst of 400. Per-IP limiter state retains at most 4,096 entries,
HTTP bodies are capped at 65,535 bytes, and graceful shutdown has a 20-second
deadline.

Every capacity and duration must be nonzero. Semaphore-backed values must not
exceed Tokio's supported maximum. The store batch size must be in `1..=65536`.
Invalid values fail validation before the database, sockets, tasks, or threads are
opened. Per-IP publishing limits may be disabled for local development, but the
global process limits cannot be disabled.

`pkarr_put_rate_limit = "smart"` trusts forwarding headers only from networks
listed in `limits.trusted_proxy_cidrs`; validation rejects smart mode when that
list is empty. Connection overload closes only the newly accepted socket,
request-capacity overload returns `503` with `Retry-After`, per-IP overload
returns `429`, and oversized extracted bodies return `413`.

Raise a production limit only after a load test at twice the proposed capacity
shows at least 30% remaining CPU, memory, and file-descriptor headroom. Capacity
rejections indicate either undersizing or a slow backing dependency. Alert on the
fixed admission metrics for active DNS/HTTP work, capacity/rate rejections,
bounded rate-limit entries, and store background failures.

# License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
