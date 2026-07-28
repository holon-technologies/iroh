use std::{
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::{
    PingTracker,
    protos::relay::Datagrams,
    tls::{CaTlsConfig, default_provider},
};
use n0_error::{AnyError as Error, Result, StackResultExt, StdResultExt};
use n0_tracing_test::traced_test;
use tokio::sync::{mpsc, oneshot};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, info, info_span};

use super::{
    ActiveRelayActor, ActiveRelayActorOptions, ActiveRelayCompletion, ActiveRelayMessage,
    ActiveRelayPrioMessage, Config, RELAY_INACTIVE_CLEANUP_TIME, RelayActor,
    RelayConnectionOptions, RelayRecvDatagram, RelaySendItem, UNDELIVERABLE_DATAGRAM_TIMEOUT,
};
use crate::{
    dns::DnsResolver,
    endpoint::EndpointLimits,
    runtime::Runtime,
    simulation::{RelayConnectError, RelayConnectRequest, RelayConnector},
    test_utils,
};

fn test_runtime(secret_key: &SecretKey) -> Arc<Runtime> {
    Arc::new(Runtime::new(
        secret_key.public(),
        Arc::new(iroh_runtime::RuntimeContext::production(Arc::new(
            iroh_runtime::NoopTraceSink,
        ))),
    ))
}

#[derive(Debug, Default)]
struct FailingRelayConnector {
    calls: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Default)]
struct PendingRelayConnector {
    calls: std::sync::atomic::AtomicUsize,
    dropped: Arc<AtomicBool>,
}

impl RelayConnector for PendingRelayConnector {
    fn connect(
        &self,
        _request: RelayConnectRequest,
    ) -> Pin<Box<dyn Future<Output = Result<iroh_relay::client::Client, RelayConnectError>> + Send>>
    {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dropped = self.dropped.clone();
        Box::pin(async move {
            struct DropSignal(Arc<AtomicBool>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _signal = DropSignal(dropped);
            std::future::pending().await
        })
    }
}

impl RelayConnector for FailingRelayConnector {
    fn connect(
        &self,
        request: RelayConnectRequest,
    ) -> Pin<Box<dyn Future<Output = Result<iroh_relay::client::Client, RelayConnectError>> + Send>>
    {
        assert_eq!(request.url().as_str(), "https://injected-relay.invalid/");
        assert_eq!(request.secret_key().public(), request.endpoint_id());
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(RelayConnectError::new("injected dial failure")) })
    }
}

#[tokio::test]
async fn active_relay_admission_limit_is_exact_and_recovers() {
    let connector = Arc::new(PendingRelayConnector::default());
    let secret_key = SecretKey::from_bytes(&[79; 32]);
    let runtime = test_runtime(&secret_key);
    let (recv_tx, _recv_rx) = mpsc::channel(8);
    let limits = EndpointLimits::default().with_max_active_relay_actors(
        std::num::NonZeroUsize::new(2).expect("nonzero test capacity"),
    );
    let config = Config {
        my_relay: Default::default(),
        secret_key,
        dns_resolver: DnsResolver::new(),
        proxy_url: None,
        ipv6_reported: Arc::new(AtomicBool::new(false)),
        tls_config: CaTlsConfig::insecure_skip_verify()
            .client_config(default_provider())
            .expect("infallible"),
        metrics: Default::default(),
        relay_map: iroh_relay::RelayMap::empty(),
        relay_connector: Some(connector),
        initial_relay: None,
        limits,
    };
    let mut actor = RelayActor::new(config, recv_tx, CancellationToken::new(), runtime);
    let first_url: RelayUrl = "https://first-relay.invalid".parse().unwrap();
    let second_url: RelayUrl = "https://second-relay.invalid".parse().unwrap();
    let third_url: RelayUrl = "https://third-relay.invalid".parse().unwrap();

    let first = actor.active_relay_handle(first_url.clone()).unwrap();
    let _second = actor.active_relay_handle(second_url).unwrap();
    assert!(
        actor.active_relay_handle(third_url.clone()).is_err(),
        "the third distinct relay must be rejected at capacity"
    );

    actor.active_relays.remove(&first_url);
    drop(first);
    let completion = tokio::time::timeout(
        Duration::from_secs(2),
        actor.active_relay_completions_rx.recv(),
    )
    .await
    .expect("removed actor must finish")
    .expect("completion channel must remain open");
    actor.active_relay_task_count = actor
        .active_relay_task_count
        .checked_sub(1)
        .expect("one active relay task");
    match completion {
        ActiveRelayCompletion::Finished(permit) | ActiveRelayCompletion::Panicked(permit) => {
            drop(permit)
        }
    }

    assert!(
        actor.active_relay_handle(third_url).is_ok(),
        "released active-relay capacity must be reusable"
    );
    actor.close_all_active_relays().await;
}

#[tokio::test]
async fn injected_connector_owns_relay_dial() {
    let connector = Arc::new(FailingRelayConnector::default());
    let (_prio_tx, prio_rx) = mpsc::channel(1);
    let (_inbox_tx, inbox_rx) = mpsc::channel(1);
    let (_send_tx, send_rx) = mpsc::channel(1);
    let (recv_tx, _recv_rx) = mpsc::channel(1);
    let url: RelayUrl = "https://injected-relay.invalid".parse().unwrap();
    let secret_key = SecretKey::from_bytes(&[77; 32]);
    let actor = ActiveRelayActor::new(ActiveRelayActorOptions {
        url: url.clone(),
        prio_inbox_: prio_rx,
        inbox: inbox_rx,
        relay_datagrams_send: send_rx,
        relay_datagrams_recv: recv_tx,
        connection_opts: RelayConnectionOptions {
            secret_key: secret_key.clone(),
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            prefer_ipv6: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            auth_token: None,
        },
        relay_connector: Some(connector.clone()),
        runtime: test_runtime(&secret_key),
        stop_token: CancellationToken::new(),
        metrics: Default::default(),
        my_relay: Default::default(),
    })
    .unwrap();

    assert!(actor.dial_relay().await.is_err());
    assert_eq!(connector.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_an_injected_dial_drops_the_owned_connector_future() {
    let connector = Arc::new(PendingRelayConnector::default());
    let (_prio_tx, prio_rx) = mpsc::channel(1);
    let (_inbox_tx, inbox_rx) = mpsc::channel(1);
    let (_send_tx, send_rx) = mpsc::channel(1);
    let (recv_tx, _recv_rx) = mpsc::channel(1);
    let url: RelayUrl = "https://cancelled-relay.invalid".parse().unwrap();
    let secret_key = SecretKey::from_bytes(&[78; 32]);
    let actor = ActiveRelayActor::new(ActiveRelayActorOptions {
        url,
        prio_inbox_: prio_rx,
        inbox: inbox_rx,
        relay_datagrams_send: send_rx,
        relay_datagrams_recv: recv_tx,
        connection_opts: RelayConnectionOptions {
            secret_key: secret_key.clone(),
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            prefer_ipv6: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            auth_token: None,
        },
        relay_connector: Some(connector.clone()),
        runtime: test_runtime(&secret_key),
        stop_token: CancellationToken::new(),
        metrics: Default::default(),
        my_relay: Default::default(),
    })
    .unwrap();

    let mut dial = Box::pin(actor.dial_relay());
    std::future::poll_fn(|cx| {
        assert!(dial.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(connector.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(!connector.dropped.load(std::sync::atomic::Ordering::SeqCst));
    drop(dial);
    assert!(connector.dropped.load(std::sync::atomic::Ordering::SeqCst));
}

/// Starts a new [`ActiveRelayActor`].
#[allow(clippy::too_many_arguments)]
fn start_active_relay_actor(
    secret_key: SecretKey,
    stop_token: CancellationToken,
    url: RelayUrl,
    prio_inbox_rx: mpsc::Receiver<ActiveRelayPrioMessage>,
    inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
    relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    span: tracing::Span,
) -> AbortOnDropHandle<()> {
    let runtime = test_runtime(&secret_key);
    let opts = ActiveRelayActorOptions {
        url,
        prio_inbox_: prio_inbox_rx,
        inbox: inbox_rx,
        relay_datagrams_send,
        relay_datagrams_recv,
        connection_opts: RelayConnectionOptions {
            secret_key,
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            prefer_ipv6: Arc::new(AtomicBool::new(true)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            auth_token: None,
        },
        relay_connector: None,
        runtime,
        stop_token,
        metrics: Default::default(),
        my_relay: Default::default(),
    };
    let task = tokio::spawn(ActiveRelayActor::new(opts).unwrap().run().instrument(span));
    AbortOnDropHandle::new(task)
}

/// Starts an [`ActiveRelayActor`] as an "iroh echo endpoint".
///
/// This actor will connect to the relay server, pretending to be an iroh endpoint, and echo
/// back any datagram it receives from the relay.  This is used by the
/// [`ActiveRelayActor`] under test to check connectivity works.
fn start_echo_endpoint(relay_url: RelayUrl) -> (EndpointId, AbortOnDropHandle<()>) {
    let secret_key = SecretKey::from_bytes(&[8u8; 32]);
    let (recv_datagram_tx, mut recv_datagram_rx) = mpsc::channel(16);
    let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
    let (prio_inbox_tx, prio_inbox_rx) = mpsc::channel(8);
    let (inbox_tx, inbox_rx) = mpsc::channel(16);
    let cancel_token = CancellationToken::new();
    let actor_task = start_active_relay_actor(
        secret_key.clone(),
        cancel_token.clone(),
        relay_url.clone(),
        prio_inbox_rx,
        inbox_rx,
        send_datagram_rx,
        recv_datagram_tx,
        info_span!("echo-endpoint"),
    );
    let echo_task = tokio::spawn({
        let relay_url = relay_url.clone();
        async move {
            loop {
                let datagram = recv_datagram_rx.recv().await;
                if let Some(recv) = datagram {
                    let RelayRecvDatagram {
                        url: _,
                        src,
                        datagrams,
                    } = recv;
                    info!(from = %src.fmt_short(), "Received datagram");
                    let send = RelaySendItem {
                        remote_endpoint: src,
                        url: relay_url.clone(),
                        datagrams,
                    };
                    send_datagram_tx.send(send).await.ok();
                }
            }
        }
        .instrument(info_span!("echo-task"))
    });
    let echo_task = AbortOnDropHandle::new(echo_task);
    let supervisor_task = tokio::spawn(async move {
        let _guard = cancel_token.drop_guard();
        // move the inboxes here so it is not dropped, as this stops the actor.
        let _prio_inbox_tx = prio_inbox_tx;
        let _inbox_tx = inbox_tx;
        tokio::select! {
            biased;
            _ = actor_task => (),
            _ = echo_task => (),
        };
    });
    let supervisor_task = AbortOnDropHandle::new(supervisor_task);
    (secret_key.public(), supervisor_task)
}

/// Sends a message to the echo endpoint, receives the response.
///
/// This takes care of retry and timeout.  Because we don't know when both the
/// endpoint-under-test and the echo endpoint will be ready and datagrams aren't queued to send
/// forever, we have to retry a few times.
async fn send_recv_echo(
    item: RelaySendItem,
    tx: &mpsc::Sender<RelaySendItem>,
    rx: &mut mpsc::Receiver<RelayRecvDatagram>,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async move {
        loop {
            let res = tokio::time::timeout(UNDELIVERABLE_DATAGRAM_TIMEOUT, async {
                tx.send(item.clone()).await.std_context("send item")?;
                let RelayRecvDatagram {
                    url: _,
                    src: _,
                    datagrams,
                } = rx.recv().await.unwrap();

                assert_eq!(datagrams, item.datagrams);

                Ok::<_, Error>(())
            })
            .await;
            if res.is_ok() {
                break;
            }
        }
    })
    .await
    .expect("overall timeout exceeded");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_active_relay_reconnect() -> Result {
    let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
    let (peer_endpoint, _echo_endpoint_task) = start_echo_endpoint(relay_url.clone());

    let secret_key = SecretKey::from_bytes(&[1u8; 32]);
    let (datagram_recv_tx, mut datagram_recv_rx) = mpsc::channel(16);
    let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
    let (_prio_inbox_tx, prio_inbox_rx) = mpsc::channel(8);
    let (inbox_tx, inbox_rx) = mpsc::channel(16);
    let cancel_token = CancellationToken::new();
    let task = start_active_relay_actor(
        secret_key,
        cancel_token.clone(),
        relay_url.clone(),
        prio_inbox_rx,
        inbox_rx,
        send_datagram_rx,
        datagram_recv_tx.clone(),
        info_span!("actor-under-test"),
    );

    // Send a datagram to our echo endpoint.
    info!("first echo");
    let hello_send_item = RelaySendItem {
        remote_endpoint: peer_endpoint,
        url: relay_url.clone(),
        datagrams: Datagrams::from(b"hello"),
    };
    send_recv_echo(
        hello_send_item.clone(),
        &send_datagram_tx,
        &mut datagram_recv_rx,
    )
    .await?;

    // Now ask to check the connection, triggering a ping but no reconnect.
    let (tx, rx) = oneshot::channel();
    inbox_tx
        .send(ActiveRelayMessage::GetLocalAddr(tx))
        .await
        .std_context("send get local addr msg")?;

    let local_addr = rx
        .await
        .std_context("wait for local addr msg")?
        .context("no local addr")?;
    info!(?local_addr, "check connection with addr");
    inbox_tx
        .send(ActiveRelayMessage::CheckConnection {
            local_ips: vec![local_addr.ip()],
        })
        .await
        .std_context("send check connection message")?;

    // Sync the ActiveRelayActor. Ping blocks it and we want to be sure it has handled
    // another inbox message before continuing.
    let (tx, rx) = oneshot::channel();
    inbox_tx
        .send(ActiveRelayMessage::GetLocalAddr(tx))
        .await
        .std_context("send get local addr msg")?;
    rx.await.std_context("recv send local addr msg")?;

    // Echo should still work.
    info!("second echo");
    send_recv_echo(
        hello_send_item.clone(),
        &send_datagram_tx,
        &mut datagram_recv_rx,
    )
    .await?;

    // Now ask to check the connection, this will reconnect without pinging because we
    // do not supply any "valid" local IP addresses.
    info!("check connection");
    inbox_tx
        .send(ActiveRelayMessage::CheckConnection {
            local_ips: Vec::new(),
        })
        .await
        .std_context("send check connection msg")?;

    // Give some time to reconnect, mostly to sort logs rather than functional.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Echo should still work.
    info!("third echo");
    send_recv_echo(
        hello_send_item.clone(),
        &send_datagram_tx,
        &mut datagram_recv_rx,
    )
    .await?;

    // Shut down the actor.
    cancel_token.cancel();
    task.await.std_context("wait for task to finish")?;

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_active_relay_inactive() -> Result {
    let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;

    let secret_key = SecretKey::from_bytes(&[1u8; 32]);
    let (datagram_recv_tx, _datagram_recv_rx) = mpsc::channel(16);
    let (_send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
    let (_prio_inbox_tx, prio_inbox_rx) = mpsc::channel(8);
    let (inbox_tx, inbox_rx) = mpsc::channel(16);
    let cancel_token = CancellationToken::new();
    let mut task = start_active_relay_actor(
        secret_key,
        cancel_token.clone(),
        relay_url,
        prio_inbox_rx,
        inbox_rx,
        send_datagram_rx,
        datagram_recv_tx,
        info_span!("actor-under-test"),
    );

    // Wait until the actor is connected to the relay server.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (tx, rx) = oneshot::channel();
            inbox_tx.send(ActiveRelayMessage::PingServer(tx)).await.ok();
            if tokio::time::timeout(Duration::from_millis(200), rx)
                .await
                .map(|resp| resp.is_ok())
                .unwrap_or_default()
            {
                break;
            }
        }
    })
    .await
    .std_context("timeout")?;

    // We now have an idling ActiveRelayActor.  If we advance time just a little it
    // should stay alive.
    info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME / 2");
    tokio::time::pause();
    tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME / 2).await;
    tokio::time::resume();

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "actor task terminated"
    );

    // If we advance time a lot it should finish.
    info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME");
    tokio::time::pause();
    tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME).await;
    tokio::time::resume();

    // We resume time for these timeouts, as there's actual I/O happening,
    // for example closing the TCP stream, so we actually need the tokio
    // runtime to idle a bit while the kernel is doing its thing.
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .is_ok(),
        "actor task still running"
    );

    cancel_token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_ping_tracker() {
    tokio::time::pause();
    let mut tracker = PingTracker::default();

    let ping0 = tracker.new_ping();

    let res = tokio::time::timeout(Duration::from_secs(1), tracker.timeout()).await;
    assert!(res.is_err(), "no ping timeout has elapsed yet");

    tracker.pong_received(ping0);
    let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
    assert!(res.is_err(), "ping completed before timeout");

    let _ping1 = tracker.new_ping();

    let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
    assert!(res.is_ok(), "ping timeout should have happened");

    let _ping2 = tracker.new_ping();

    tokio::time::sleep(Duration::from_secs(10)).await;
    let res = tokio::time::timeout(Duration::from_millis(1), tracker.timeout()).await;
    assert!(res.is_ok(), "ping timeout happened in the past");

    let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
    assert!(res.is_err(), "ping timeout should only happen once");
}

#[test]
fn test_home_relay_watch_url_guard() {
    use super::{HomeRelayWatch, RelayConnectionState};
    use crate::endpoint::RelayStatus;

    let watch = HomeRelayWatch::default();
    let a: RelayUrl = "https://a.example.com".parse().unwrap();
    let b: RelayUrl = "https://b.example.com".parse().unwrap();

    // Actor A becomes home and connects
    watch.set(a.clone(), RelayConnectionState::Connecting);
    watch.set_status(&a, RelayConnectionState::Connected);
    assert_eq!(
        watch.get(),
        Some(RelayStatus::new(a.clone(), RelayConnectionState::Connected)),
    );

    // RelayActor migrates home to B
    watch.set(b.clone(), RelayConnectionState::Connecting);

    // Old actor A tries to write -- rejected because URL changed
    watch.set_status(&a, RelayConnectionState::Disconnected { last_error: None });
    assert_eq!(
        watch.get(),
        Some(RelayStatus::new(
            b.clone(),
            RelayConnectionState::Connecting
        )),
    );

    // Actor B writes normally
    watch.set_status(&b, RelayConnectionState::Connected);
    assert_eq!(
        watch.get(),
        Some(RelayStatus::new(b, RelayConnectionState::Connected)),
    );
}
