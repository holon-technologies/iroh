use std::{
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use proto::{ConnectionHandle, EndpointEvent, NetworkChangeHint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::{VarInt, runtime::UdpSender};

/// Default maximum number of simultaneously active connections in one endpoint.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2_048;
/// Default maximum queued packet events for one connection.
pub const DEFAULT_MAX_PACKET_EVENTS_PER_CONNECTION: usize = 32;
/// Default maximum queued packet bytes across one endpoint.
pub const DEFAULT_MAX_PACKET_BYTES_PER_ENDPOINT: u32 = 64 * 1024 * 1024;
/// Default maximum queued bidirectional nonterminal control events.
pub const DEFAULT_MAX_CONTROL_EVENTS_PER_ENDPOINT: usize = 4_096;

/// Finite limits for one endpoint's active connections and internal event queues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventQueueLimits {
    max_connections: NonZeroUsize,
    max_packet_events_per_connection: NonZeroUsize,
    max_packet_bytes_per_endpoint: NonZeroU32,
    max_control_events_per_endpoint: NonZeroUsize,
}

impl EventQueueLimits {
    /// Creates an explicit set of nonzero endpoint event limits.
    pub const fn new(
        max_connections: NonZeroUsize,
        max_packet_events_per_connection: NonZeroUsize,
        max_packet_bytes_per_endpoint: NonZeroU32,
        max_control_events_per_endpoint: NonZeroUsize,
    ) -> Self {
        Self {
            max_connections,
            max_packet_events_per_connection,
            max_packet_bytes_per_endpoint,
            max_control_events_per_endpoint,
        }
    }

    /// Returns the maximum number of simultaneously active connections.
    pub const fn max_connections(self) -> NonZeroUsize {
        self.max_connections
    }

    /// Returns the per-connection queued packet-event maximum.
    pub const fn max_packet_events_per_connection(self) -> NonZeroUsize {
        self.max_packet_events_per_connection
    }

    /// Returns the endpoint-wide queued packet-byte maximum.
    pub const fn max_packet_bytes_per_endpoint(self) -> NonZeroU32 {
        self.max_packet_bytes_per_endpoint
    }

    /// Returns the endpoint-wide queued nonterminal control-event maximum.
    pub const fn max_control_events_per_endpoint(self) -> NonZeroUsize {
        self.max_control_events_per_endpoint
    }
}

impl Default for EventQueueLimits {
    fn default() -> Self {
        Self::new(
            NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS)
                .expect("default connection limit is nonzero"),
            NonZeroUsize::new(DEFAULT_MAX_PACKET_EVENTS_PER_CONNECTION)
                .expect("default packet-event limit is nonzero"),
            NonZeroU32::new(DEFAULT_MAX_PACKET_BYTES_PER_ENDPOINT)
                .expect("default packet-byte limit is nonzero"),
            NonZeroUsize::new(DEFAULT_MAX_CONTROL_EVENTS_PER_ENDPOINT)
                .expect("default control-event limit is nonzero"),
        )
    }
}

/// Current, high-water, and rejection counters for endpoint event admission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventQueueStats {
    /// Current number of active connections holding event capacity.
    pub active_connections: usize,
    /// High-water number of active connections.
    pub active_connections_high_water: usize,
    /// Current number of queued packet events.
    pub packet_events_current: usize,
    /// High-water number of queued packet events.
    pub packet_events_high_water: usize,
    /// Largest queued packet-event count observed on any one connection.
    pub packet_events_per_connection_high_water: usize,
    /// Current number of queued packet bytes.
    pub packet_bytes_current: usize,
    /// High-water number of queued packet bytes.
    pub packet_bytes_high_water: usize,
    /// Current number of queued nonterminal control events.
    pub control_events_current: usize,
    /// High-water number of queued nonterminal control events.
    pub control_events_high_water: usize,
    /// Packet events rejected by the per-connection item limit.
    pub packet_event_rejections: u64,
    /// Packet events rejected by the endpoint-wide byte limit.
    pub packet_byte_rejections: u64,
    /// Connections rejected by the endpoint connection limit.
    pub connection_rejections: u64,
    /// Nonterminal events rejected by the endpoint control-event limit.
    pub control_event_rejections: u64,
    /// Whether any accounting counter exhausted and latched the queue closed.
    pub counter_exhausted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueAdmissionError {
    ConnectionsFull,
    PacketItemsFull,
    PacketBytesFull,
    ControlEventsFull,
    CounterExhausted,
}

#[derive(Debug)]
pub(crate) enum ConnectionEvent {
    Close { error_code: VarInt, reason: Bytes },
    Proto(proto::ConnectionEvent),
    Rebind(Pin<Box<dyn UdpSender>>),
    LocalAddressChanged(Option<Arc<dyn NetworkChangeHint + Sync + Send>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventSendError {
    Closed,
    Admission(QueueAdmissionError),
    TerminalCreditExhausted,
}

#[derive(Debug)]
struct Counter {
    current: AtomicUsize,
    high_water: AtomicUsize,
    rejections: AtomicU64,
}

impl Counter {
    const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            rejections: AtomicU64::new(0),
        }
    }

    fn increment(&self, amount: usize, failed: &AtomicBool) -> Result<(), QueueAdmissionError> {
        let previous = self
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(amount)
            })
            .map_err(|_| {
                failed.store(true, Ordering::Release);
                QueueAdmissionError::CounterExhausted
            })?;
        let current = previous
            .checked_add(amount)
            .expect("successful checked counter update cannot overflow");
        self.high_water.fetch_max(current, Ordering::AcqRel);
        Ok(())
    }

    fn decrement(&self, amount: usize) {
        let result = self
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(amount)
            });
        assert!(
            result.is_ok(),
            "event queue current counter must not underflow"
        );
    }

    fn reject(&self, failed: &AtomicBool) -> Result<(), QueueAdmissionError> {
        self.rejections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(|_| ())
            .map_err(|_| {
                failed.store(true, Ordering::Release);
                QueueAdmissionError::CounterExhausted
            })
    }
}

#[derive(Debug)]
pub(crate) struct QueueBudgets {
    limits: EventQueueLimits,
    connections: Arc<Semaphore>,
    packet_bytes: Arc<Semaphore>,
    control_events: Arc<Semaphore>,
    connection_count: Counter,
    packet_event_count: Counter,
    packet_events_per_connection_high_water: AtomicUsize,
    packet_byte_count: Counter,
    control_event_count: Counter,
    failed: AtomicBool,
}

impl QueueBudgets {
    pub(crate) fn new(limits: EventQueueLimits) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(limits.max_connections.get())),
            packet_bytes: Arc::new(Semaphore::new(
                usize::try_from(limits.max_packet_bytes_per_endpoint.get())
                    .expect("u32 packet-byte limit fits usize on supported targets"),
            )),
            control_events: Arc::new(Semaphore::new(limits.max_control_events_per_endpoint.get())),
            limits,
            connection_count: Counter::new(),
            packet_event_count: Counter::new(),
            packet_events_per_connection_high_water: AtomicUsize::new(0),
            packet_byte_count: Counter::new(),
            control_event_count: Counter::new(),
            failed: AtomicBool::new(false),
        }
    }

    pub(crate) fn try_new_connection(
        self: &Arc<Self>,
    ) -> Result<Arc<ConnectionBudget>, QueueAdmissionError> {
        self.check_failed()?;
        let permit = self.connections.clone().try_acquire_owned().map_err(|_| {
            self.connection_count
                .reject(&self.failed)
                .map(|_| QueueAdmissionError::ConnectionsFull)
                .unwrap_or(QueueAdmissionError::CounterExhausted)
        })?;
        if let Err(error) = self.connection_count.increment(1, &self.failed) {
            drop(permit);
            return Err(error);
        }
        Ok(Arc::new(ConnectionBudget {
            budgets: self.clone(),
            packet_events: Arc::new(Semaphore::new(
                self.limits.max_packet_events_per_connection.get(),
            )),
            _connection_permit: permit,
        }))
    }

    pub(crate) fn try_acquire_control(
        self: &Arc<Self>,
    ) -> Result<ControlPermit, QueueAdmissionError> {
        self.check_failed()?;
        let permit = self
            .control_events
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.control_event_count
                    .reject(&self.failed)
                    .map(|_| QueueAdmissionError::ControlEventsFull)
                    .unwrap_or(QueueAdmissionError::CounterExhausted)
            })?;
        if let Err(error) = self.control_event_count.increment(1, &self.failed) {
            drop(permit);
            return Err(error);
        }
        Ok(ControlPermit {
            budgets: self.clone(),
            _permit: permit,
        })
    }

    pub(crate) fn stats(&self) -> EventQueueStats {
        EventQueueStats {
            active_connections: self.connection_count.current.load(Ordering::Acquire),
            active_connections_high_water: self.connection_count.high_water.load(Ordering::Acquire),
            packet_events_current: self.packet_event_count.current.load(Ordering::Acquire),
            packet_events_high_water: self.packet_event_count.high_water.load(Ordering::Acquire),
            packet_events_per_connection_high_water: self
                .packet_events_per_connection_high_water
                .load(Ordering::Acquire),
            packet_bytes_current: self.packet_byte_count.current.load(Ordering::Acquire),
            packet_bytes_high_water: self.packet_byte_count.high_water.load(Ordering::Acquire),
            control_events_current: self.control_event_count.current.load(Ordering::Acquire),
            control_events_high_water: self.control_event_count.high_water.load(Ordering::Acquire),
            packet_event_rejections: self.packet_event_count.rejections.load(Ordering::Acquire),
            packet_byte_rejections: self.packet_byte_count.rejections.load(Ordering::Acquire),
            connection_rejections: self.connection_count.rejections.load(Ordering::Acquire),
            control_event_rejections: self.control_event_count.rejections.load(Ordering::Acquire),
            counter_exhausted: self.failed.load(Ordering::Acquire),
        }
    }

    fn check_failed(&self) -> Result<(), QueueAdmissionError> {
        if self.failed.load(Ordering::Acquire) {
            Err(QueueAdmissionError::CounterExhausted)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionBudget {
    budgets: Arc<QueueBudgets>,
    packet_events: Arc<Semaphore>,
    _connection_permit: OwnedSemaphorePermit,
}

impl ConnectionBudget {
    pub(crate) fn try_acquire_packet(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<PacketPermit, QueueAdmissionError> {
        self.budgets.check_failed()?;
        let item_permit = self
            .packet_events
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.budgets
                    .packet_event_count
                    .reject(&self.budgets.failed)
                    .map(|_| QueueAdmissionError::PacketItemsFull)
                    .unwrap_or(QueueAdmissionError::CounterExhausted)
            })?;
        let Ok(byte_count) = u32::try_from(bytes) else {
            drop(item_permit);
            let error = self
                .budgets
                .packet_byte_count
                .reject(&self.budgets.failed)
                .map(|_| QueueAdmissionError::PacketBytesFull)
                .unwrap_or(QueueAdmissionError::CounterExhausted);
            return Err(error);
        };
        let Ok(byte_permit) = self
            .budgets
            .packet_bytes
            .clone()
            .try_acquire_many_owned(byte_count)
        else {
            drop(item_permit);
            let error = self
                .budgets
                .packet_byte_count
                .reject(&self.budgets.failed)
                .map(|_| QueueAdmissionError::PacketBytesFull)
                .unwrap_or(QueueAdmissionError::CounterExhausted);
            return Err(error);
        };

        if let Err(error) = self
            .budgets
            .packet_event_count
            .increment(1, &self.budgets.failed)
        {
            drop(item_permit);
            drop(byte_permit);
            return Err(error);
        }
        let byte_count = usize::try_from(byte_count)
            .expect("u32 packet-byte count fits usize on supported targets");
        if let Err(error) = self
            .budgets
            .packet_byte_count
            .increment(byte_count, &self.budgets.failed)
        {
            self.budgets.packet_event_count.decrement(1);
            drop(item_permit);
            drop(byte_permit);
            return Err(error);
        }
        let per_connection = self
            .budgets
            .limits
            .max_packet_events_per_connection
            .get()
            .checked_sub(self.packet_events.available_permits())
            .expect("available packet-event permits cannot exceed the configured maximum");
        self.budgets
            .packet_events_per_connection_high_water
            .fetch_max(per_connection, Ordering::AcqRel);
        Ok(PacketPermit {
            budgets: self.budgets.clone(),
            byte_count,
            _item_permit: item_permit,
            _byte_permit: byte_permit,
        })
    }
}

impl Drop for ConnectionBudget {
    fn drop(&mut self) {
        self.budgets.connection_count.decrement(1);
    }
}

#[derive(Debug)]
pub(crate) struct PacketPermit {
    budgets: Arc<QueueBudgets>,
    byte_count: usize,
    _item_permit: OwnedSemaphorePermit,
    _byte_permit: OwnedSemaphorePermit,
}

impl Drop for PacketPermit {
    fn drop(&mut self) {
        self.budgets.packet_event_count.decrement(1);
        self.budgets.packet_byte_count.decrement(self.byte_count);
    }
}

#[derive(Debug)]
pub(crate) struct ControlPermit {
    budgets: Arc<QueueBudgets>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ControlPermit {
    fn drop(&mut self) {
        self.budgets.control_event_count.decrement(1);
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "packet events are already stored in bounded heap-backed channel nodes; boxing adds one allocation per packet without reducing the queue ceiling"
)]
#[derive(Debug)]
enum QueuedConnectionEvent {
    Packet(proto::ConnectionEvent, PacketPermit),
    Close,
    Rebind,
    LocalAddressChanged,
}

#[derive(Debug, Default)]
struct CoalescedConnectionEvents {
    close: Option<(VarInt, Bytes)>,
    close_marker_pending: bool,
    rebind: Option<Pin<Box<dyn UdpSender>>>,
    rebind_marker_pending: bool,
    local_address_changed: Option<Option<Arc<dyn NetworkChangeHint + Sync + Send>>>,
    local_address_changed_marker_pending: bool,
}

#[derive(Debug)]
pub(crate) struct ConnectionEventSender {
    raw: mpsc::UnboundedSender<QueuedConnectionEvent>,
    generated: mpsc::UnboundedSender<(proto::ConnectionEvent, ControlPermit)>,
    coalesced: Arc<Mutex<CoalescedConnectionEvents>>,
    budget: Arc<ConnectionBudget>,
}

impl ConnectionEventSender {
    pub(crate) fn channel(budget: Arc<ConnectionBudget>) -> (Self, ConnectionEventReceiver) {
        let (raw, raw_receiver) = mpsc::unbounded_channel();
        let (generated, generated_receiver) = mpsc::unbounded_channel();
        let coalesced = Arc::new(Mutex::new(CoalescedConnectionEvents::default()));
        (
            Self {
                raw,
                generated,
                coalesced: coalesced.clone(),
                budget,
            },
            ConnectionEventReceiver {
                raw: raw_receiver,
                generated: generated_receiver,
                coalesced,
            },
        )
    }

    pub(crate) fn send_packet(
        &self,
        event: proto::ConnectionEvent,
        bytes: usize,
    ) -> Result<(), EventSendError> {
        let permit = self
            .budget
            .try_acquire_packet(bytes)
            .map_err(EventSendError::Admission)?;
        self.raw
            .send(QueuedConnectionEvent::Packet(event, permit))
            .map_err(|_| EventSendError::Closed)
    }

    pub(crate) fn send_generated(
        &self,
        event: proto::ConnectionEvent,
        permit: ControlPermit,
    ) -> Result<(), EventSendError> {
        self.generated
            .send((event, permit))
            .map_err(|_| EventSendError::Closed)
    }

    pub(crate) fn send_close(
        &self,
        error_code: VarInt,
        reason: Bytes,
    ) -> Result<(), EventSendError> {
        let mut coalesced = self
            .coalesced
            .lock()
            .expect("coalesced event mutex poisoned");
        let enqueue = !coalesced.close_marker_pending;
        coalesced.close = Some((error_code, reason));
        if enqueue && self.raw.send(QueuedConnectionEvent::Close).is_err() {
            coalesced.close = None;
            return Err(EventSendError::Closed);
        }
        coalesced.close_marker_pending = true;
        Ok(())
    }

    pub(crate) fn send_rebind(
        &self,
        sender: Pin<Box<dyn UdpSender>>,
    ) -> Result<(), EventSendError> {
        let mut coalesced = self
            .coalesced
            .lock()
            .expect("coalesced event mutex poisoned");
        let enqueue = !coalesced.rebind_marker_pending;
        coalesced.rebind = Some(sender);
        if enqueue && self.raw.send(QueuedConnectionEvent::Rebind).is_err() {
            coalesced.rebind = None;
            return Err(EventSendError::Closed);
        }
        coalesced.rebind_marker_pending = true;
        Ok(())
    }

    pub(crate) fn send_local_address_changed(
        &self,
        hint: Option<Arc<dyn NetworkChangeHint + Sync + Send>>,
    ) -> Result<(), EventSendError> {
        let mut coalesced = self
            .coalesced
            .lock()
            .expect("coalesced event mutex poisoned");
        let enqueue = !coalesced.local_address_changed_marker_pending;
        coalesced.local_address_changed = Some(hint);
        if enqueue
            && self
                .raw
                .send(QueuedConnectionEvent::LocalAddressChanged)
                .is_err()
        {
            coalesced.local_address_changed = None;
            return Err(EventSendError::Closed);
        }
        coalesced.local_address_changed_marker_pending = true;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionEventReceiver {
    raw: mpsc::UnboundedReceiver<QueuedConnectionEvent>,
    generated: mpsc::UnboundedReceiver<(proto::ConnectionEvent, ControlPermit)>,
    coalesced: Arc<Mutex<CoalescedConnectionEvents>>,
}

impl ConnectionEventReceiver {
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<ConnectionEvent>> {
        loop {
            {
                let mut coalesced = self
                    .coalesced
                    .lock()
                    .expect("coalesced event mutex poisoned");
                if let Some((error_code, reason)) = coalesced.close.take() {
                    return Poll::Ready(Some(ConnectionEvent::Close { error_code, reason }));
                }
                if let Some(sender) = coalesced.rebind.take() {
                    return Poll::Ready(Some(ConnectionEvent::Rebind(sender)));
                }
                if let Some(hint) = coalesced.local_address_changed.take() {
                    return Poll::Ready(Some(ConnectionEvent::LocalAddressChanged(hint)));
                }
            }

            let generated_closed = match self.generated.poll_recv(cx) {
                Poll::Ready(Some((event, permit))) => {
                    drop(permit);
                    return Poll::Ready(Some(ConnectionEvent::Proto(event)));
                }
                Poll::Ready(None) => true,
                Poll::Pending => false,
            };

            let queued = match self.raw.poll_recv(cx) {
                Poll::Ready(Some(queued)) => queued,
                Poll::Ready(None) if generated_closed => return Poll::Ready(None),
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            };
            match queued {
                QueuedConnectionEvent::Packet(event, permit) => {
                    drop(permit);
                    return Poll::Ready(Some(ConnectionEvent::Proto(event)));
                }
                QueuedConnectionEvent::Close => {
                    self.coalesced
                        .lock()
                        .expect("coalesced event mutex poisoned")
                        .close_marker_pending = false;
                }
                QueuedConnectionEvent::Rebind => {
                    self.coalesced
                        .lock()
                        .expect("coalesced event mutex poisoned")
                        .rebind_marker_pending = false;
                }
                QueuedConnectionEvent::LocalAddressChanged => {
                    self.coalesced
                        .lock()
                        .expect("coalesced event mutex poisoned")
                        .local_address_changed_marker_pending = false;
                }
            }
        }
    }
}

#[derive(Debug)]
struct QueuedEndpointEvent {
    handle: ConnectionHandle,
    event: EndpointEvent,
    control: Option<ControlPermit>,
}

#[derive(Clone, Debug)]
pub(crate) struct EndpointEventQueueSender {
    raw: mpsc::UnboundedSender<QueuedEndpointEvent>,
    budgets: Arc<QueueBudgets>,
}

impl EndpointEventQueueSender {
    pub(crate) fn channel(budgets: Arc<QueueBudgets>) -> (Self, EndpointEventQueueReceiver) {
        let (raw, receiver) = mpsc::unbounded_channel();
        (
            Self { raw, budgets },
            EndpointEventQueueReceiver { raw: receiver },
        )
    }

    pub(crate) fn for_connection(
        &self,
        handle: ConnectionHandle,
        budget: Arc<ConnectionBudget>,
    ) -> EndpointEventSender {
        EndpointEventSender {
            raw: self.raw.clone(),
            budgets: self.budgets.clone(),
            handle,
            terminal_events: Arc::new(AtomicU8::new(0)),
            _connection_budget: budget,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EndpointEventSender {
    raw: mpsc::UnboundedSender<QueuedEndpointEvent>,
    budgets: Arc<QueueBudgets>,
    handle: ConnectionHandle,
    terminal_events: Arc<AtomicU8>,
    _connection_budget: Arc<ConnectionBudget>,
}

impl EndpointEventSender {
    pub(crate) fn send(&self, event: EndpointEvent) -> Result<(), EventSendError> {
        const DRAINING_SENT: u8 = 1;
        const DRAINED_SENT: u8 = 2;

        let terminal_flag = if event.is_draining() {
            Some(DRAINING_SENT)
        } else if event.is_drained() {
            Some(DRAINED_SENT)
        } else {
            None
        };
        let control = if terminal_flag.is_some() {
            None
        } else {
            Some(
                self.budgets
                    .try_acquire_control()
                    .map_err(EventSendError::Admission)?,
            )
        };
        if let Some(flag) = terminal_flag {
            self.terminal_events
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |sent| {
                    if sent & flag == 0 {
                        Some(sent | flag)
                    } else {
                        None
                    }
                })
                .map_err(|_| EventSendError::TerminalCreditExhausted)?;
        }
        if self
            .raw
            .send(QueuedEndpointEvent {
                handle: self.handle,
                event,
                control,
            })
            .is_err()
        {
            if let Some(flag) = terminal_flag {
                let previous = self.terminal_events.fetch_and(!flag, Ordering::AcqRel);
                assert_ne!(
                    previous & flag,
                    0,
                    "failed terminal send must release an acquired terminal credit"
                );
            }
            return Err(EventSendError::Closed);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct DequeuedEndpointEvent {
    pub(crate) handle: ConnectionHandle,
    pub(crate) event: EndpointEvent,
    control: Option<ControlPermit>,
}

impl DequeuedEndpointEvent {
    pub(crate) fn into_parts(self) -> (ConnectionHandle, EndpointEvent, Option<ControlPermit>) {
        (self.handle, self.event, self.control)
    }
}

#[derive(Debug)]
pub(crate) struct EndpointEventQueueReceiver {
    raw: mpsc::UnboundedReceiver<QueuedEndpointEvent>,
}

impl EndpointEventQueueReceiver {
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<DequeuedEndpointEvent>> {
        self.raw.poll_recv(cx).map(|event| {
            event.map(|event| DequeuedEndpointEvent {
                handle: event.handle,
                event: event.event,
                control: event.control,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
    };

    use super::{EventQueueLimits, QueueAdmissionError, QueueBudgets};

    fn limits(
        connections: usize,
        packet_events: usize,
        packet_bytes: u32,
        control_events: usize,
    ) -> EventQueueLimits {
        EventQueueLimits::new(
            NonZeroUsize::new(connections).unwrap(),
            NonZeroUsize::new(packet_events).unwrap(),
            NonZeroU32::new(packet_bytes).unwrap(),
            NonZeroUsize::new(control_events).unwrap(),
        )
    }

    #[test]
    fn packet_item_and_byte_budgets_accept_exact_limits_and_reject_the_first_over() {
        let budgets = Arc::new(QueueBudgets::new(limits(1, 2, 5, 2)));
        let connection = budgets.try_new_connection().unwrap();
        let first = connection.try_acquire_packet(3).unwrap();
        let second = connection.try_acquire_packet(2).unwrap();

        assert!(matches!(
            connection.try_acquire_packet(1),
            Err(QueueAdmissionError::PacketItemsFull)
        ));
        assert_eq!(budgets.stats().packet_events_current, 2);
        assert_eq!(budgets.stats().packet_events_per_connection_high_water, 2);
        assert_eq!(budgets.stats().packet_bytes_current, 5);

        drop(first);
        let exact_replacement = connection.try_acquire_packet(3).unwrap();
        drop(second);
        drop(exact_replacement);

        let exact_bytes = connection.try_acquire_packet(5).unwrap();
        assert!(matches!(
            connection.try_acquire_packet(1),
            Err(QueueAdmissionError::PacketBytesFull)
        ));
        drop(exact_bytes);
        assert_eq!(budgets.stats().packet_events_current, 0);
        assert_eq!(budgets.stats().packet_bytes_current, 0);
    }

    #[test]
    fn connection_and_control_budgets_are_conserved() {
        let budgets = Arc::new(QueueBudgets::new(limits(1, 2, 5, 2)));
        let connection = budgets.try_new_connection().unwrap();
        assert!(matches!(
            budgets.try_new_connection(),
            Err(QueueAdmissionError::ConnectionsFull)
        ));

        let first = budgets.try_acquire_control().unwrap();
        let second = budgets.try_acquire_control().unwrap();
        assert!(matches!(
            budgets.try_acquire_control(),
            Err(QueueAdmissionError::ControlEventsFull)
        ));
        assert_eq!(budgets.stats().control_events_current, 2);

        drop(first);
        let replacement = budgets.try_acquire_control().unwrap();
        drop(second);
        drop(replacement);
        drop(connection);
        assert_eq!(budgets.stats().active_connections, 0);
        assert_eq!(budgets.stats().control_events_current, 0);
    }
}
