use super::*;

/// WebSocket GUID needed for accepting websocket connections, see RFC 6455 (<https://www.rfc-editor.org/rfc/rfc6455>) section 1.3
const SEC_WEBSOCKET_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Timeout for a connection to finish the TLS and WebSocket upgrade handshakes.
///
/// The connection is aborted if the connection does not complete the TLS handshake
/// and establishes relay protocol WebSocket stream within this timeout.
pub(super) const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// Derives the accept key for WebSocket handshake according to RFC 6455.
/// Takes the client's Sec-WebSocket-Key value and returns the calculated accept key.
pub(super) fn derive_accept_key(client_key: &HeaderValue) -> String {
    use sha1::Digest;

    let mut sha1 = sha1::Sha1::new();
    sha1.update(client_key.as_bytes());
    sha1.update(SEC_WEBSOCKET_ACCEPT_GUID);
    data_encoding::BASE64.encode(&sha1.finalize())
}

#[stack_error(derive, add_meta)]
pub(super) enum RelayUpgradeReqError {
    #[error("missing header: {header}")]
    MissingHeader { header: http::HeaderName },
    #[error("invalid header value for {header}: {details}")]
    InvalidHeader {
        header: http::HeaderName,
        details: String,
    },
    #[error(
        "invalid header value for {SEC_WEBSOCKET_VERSION}: unsupported websocket version, only supporting {SUPPORTED_WEBSOCKET_VERSION}"
    )]
    UnsupportedWebsocketVersion,
    #[error(
        "invalid header value for {SEC_WEBSOCKET_PROTOCOL}: unsupported relay version: we support {we_support} but you only provide {you_support}"
    )]
    UnsupportedRelayVersion {
        we_support: String,
        you_support: String,
    },
}

impl RelayServiceWithNotify {
    pub(super) fn build_response(&self) -> http::response::Builder {
        let mut res = Response::builder();
        for (key, value) in self.service.0.headers.iter() {
            res = res.header(key, value);
        }
        res
    }

    /// Upgrades the HTTP connection to the relay protocol, runs relay client.
    pub(super) fn handle_relay_ws_upgrade(
        &self,
        mut req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, RelayUpgradeReqError> {
        fn expect_header(
            req: &Request<Incoming>,
            header: http::HeaderName,
        ) -> Result<&HeaderValue, RelayUpgradeReqError> {
            req.headers()
                .get(&header)
                .ok_or_else(|| e!(RelayUpgradeReqError::MissingHeader { header }))
        }

        let upgrade_header = expect_header(&req, UPGRADE)?;
        ensure!(
            upgrade_header == HeaderValue::from_static(WEBSOCKET_UPGRADE_PROTOCOL),
            RelayUpgradeReqError::InvalidHeader {
                header: UPGRADE,
                details: format!("value must be {WEBSOCKET_UPGRADE_PROTOCOL}")
            }
        );

        let key = expect_header(&req, SEC_WEBSOCKET_KEY)?.clone();
        let version = expect_header(&req, SEC_WEBSOCKET_VERSION)?.clone();

        ensure!(
            version.as_bytes() == SUPPORTED_WEBSOCKET_VERSION.as_bytes(),
            RelayUpgradeReqError::UnsupportedWebsocketVersion
        );

        let subprotocols = expect_header(&req, SEC_WEBSOCKET_PROTOCOL)?
            .to_str()
            .ok()
            .ok_or_else(|| {
                e!(RelayUpgradeReqError::InvalidHeader {
                    header: SEC_WEBSOCKET_PROTOCOL,
                    details: "header value is not ascii".to_string()
                })
            })?;
        let protocol_version = subprotocols
            .split(",")
            .map(|s| s.trim())
            .filter_map(ProtocolVersion::match_from_str)
            .max()
            .ok_or_else(|| {
                e!(RelayUpgradeReqError::UnsupportedRelayVersion {
                    we_support: ProtocolVersion::all_joined(),
                    you_support: subprotocols.to_string()
                })
            })?;

        // Setup a future that will eventually receive the upgraded
        // connection and talk a new protocol, and spawn the future
        // into the runtime.
        //
        // Note: This can't possibly be fulfilled until the 101 response
        // is returned below, so it's better to spawn this future instead
        // waiting for it to complete to then return a response.
        tokio::task::spawn({
            let this = self.clone();
            async move {
                match hyper::upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        let (parts, _) = req.into_parts();
                        if let Err(err) = this
                            .service
                            .0
                            .relay_connection_handler(upgraded, parts, protocol_version)
                            .await
                        {
                            warn!("error accepting upgraded connection: {err:#}",);
                        } else {
                            // We have passed the connection to the relay protocol handler,
                            // thus we trigger the on_establish notification so that timeouts
                            // on the upper layer will be cleared.
                            release_establishment_lease(&this.establishment_lease);
                            this.on_establish.notify_waiters();
                            debug!("upgraded connection completed");
                        };
                    }
                    Err(err) => warn!("upgrade error: {err:#}"),
                }
            }
            .instrument(info_span!("handler"))
        });

        // Now return a 101 Response saying we agree to the upgrade to the
        // websocket upgrade protocol
        Ok(self
            .build_response()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(
                UPGRADE,
                HeaderValue::from_static(WEBSOCKET_UPGRADE_PROTOCOL),
            )
            .header(SEC_WEBSOCKET_ACCEPT, derive_accept_key(&key))
            .header(SEC_WEBSOCKET_PROTOCOL, protocol_version.to_header_value())
            .header(CONNECTION, "upgrade")
            .body(body_full("switching to websocket protocol"))
            .expect("valid body"))
    }
}
