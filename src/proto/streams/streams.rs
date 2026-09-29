use std::{
    collections::VecDeque,
    fmt, io,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, Response};
use tokio::io::AsyncWrite;

use super::{
    frame::{Priorities, PseudoOrder, StreamDependency},
    recv::RecvHeaderBlockError,
    store::{self, Entry, Resolve, Store},
    sync::Mutex,
    Buffer, Config, Counts, Prioritized, Recv, Send, Stream, StreamId,
};
use crate::{
    client,
    codec::{Codec, SendError, UserError},
    ext::{
        FollowingFrame, FrameLog, HeaderOrder, HeadersFrame, HeadersFrameOptions, PrefaceFrame,
        Protocol,
    },
    frame::{self, Frame, Reason},
    proto,
    proto::{peer, Error, Initiator, Open, Peer, WindowSize},
    server, tracing,
};

#[derive(Debug)]
pub(crate) struct Streams<B, P>
where
    P: Peer,
{
    /// Holds most of the connection and stream related state for processing
    /// HTTP/2 frames associated with streams.
    inner: Arc<Mutex<Inner>>,

    /// This is the queue of frames to be written to the wire. This is split out
    /// to avoid requiring a `B` generic on all public API types even if `B` is
    /// not technically required.
    ///
    /// Currently, splitting this out requires a second `Arc` + `Mutex`.
    /// However, it should be possible to avoid this duplication with a little
    /// bit of unsafe code. This optimization has been postponed until it has
    /// been shown to be necessary.
    send_buffer: Arc<SendBuffer<B>>,

    _p: ::std::marker::PhantomData<P>,
}

// Like `Streams` but with a `peer::Dyn` field instead of a static `P: Peer` type parameter.
// Ensures that the methods only get one instantiation, instead of two (client and server)
#[derive(Debug)]
pub(crate) struct DynStreams<'a, B> {
    inner: &'a Mutex<Inner>,

    send_buffer: &'a SendBuffer<B>,

    peer: peer::Dyn,
}

/// Reference to the stream state
#[derive(Debug)]
pub(crate) struct StreamRef<B> {
    opaque: OpaqueStreamRef,
    send_buffer: Arc<SendBuffer<B>>,
}

/// Reference to the stream state that hides the send data chunk generic
pub(crate) struct OpaqueStreamRef {
    inner: Arc<Mutex<Inner>>,
    key: store::Key,
}

/// Fields needed to manage state related to managing the set of streams. This
/// is mostly split out to make ownership happy.
///
/// TODO: better name
#[derive(Debug)]
struct Inner {
    /// Tracks send & recv stream concurrency.
    counts: Counts,

    /// Connection level state and performs actions on streams
    actions: Actions,

    /// Stores stream state
    store: Store,

    /// The number of stream refs to this shared state.
    refs: usize,

    /// Headers stream dependency
    headers_stream_dependency: Option<StreamDependency>,

    /// Pseudo order of the headers stream
    headers_pseudo_order: Option<PseudoOrder>,

    /// Priority of the headers stream
    priorities: Option<Priorities>,

    /// Frames to send right ahead of the first request's HEADERS
    preface_frames: Vec<PrefaceFrame>,

    /// Frames to send on the live connection (see [`Control`]), in order
    control: VecDeque<ControlFrame>,

    /// Logs the frames sent, when recording them
    frame_log: Option<FrameLog>,

    /// Logs the frames received, when recording them
    received_frame_log: Option<FrameLog>,

    /// The streams opened for requests carrying their recorded stream id (see
    /// [`HeadersFrameOptions::recorded_stream_id`]), by that id, newest last
    recorded_streams: VecDeque<(u32, StreamId)>,
}

/// The PRIORITY_UPDATE frame type (RFC 9218).
const PRIORITY_UPDATE: u8 = 0x10;

/// How many of the streams opened for requests carrying their recorded stream id are
/// kept, to renumber the dependencies of the requests after them.
const RECORDED_STREAMS: usize = 256;

#[derive(Debug)]
struct Actions {
    /// Manages state transitions initiated by receiving frames
    recv: Recv,

    /// Manages state transitions initiated by sending frames
    send: Send,

    /// Task that calls `poll_complete`.
    task: Option<Waker>,

    /// If the connection errors, a copy is kept for any StreamRefs.
    conn_error: Option<proto::Error>,
}

/// Contains the buffer of frames to be written to the wire.
#[derive(Debug)]
struct SendBuffer<B> {
    inner: Mutex<Buffer<Frame<B>>>,
}

// ===== impl Streams =====

impl<B, P> Streams<B, P>
where
    B: Buf,
    P: Peer,
{
    pub fn new(config: Config) -> Self {
        let peer = P::r#dyn();

        Streams {
            inner: Inner::new(peer, config),
            send_buffer: Arc::new(SendBuffer::new()),

            _p: ::std::marker::PhantomData,
        }
    }

    pub fn set_target_connection_window_size(&mut self, size: WindowSize) -> Result<(), Reason> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        me.actions
            .recv
            .set_target_connection_window(size, &mut me.actions.task)
    }

    pub fn next_incoming(&mut self) -> Option<StreamRef<B>> {
        let mut me = self.inner.lock();
        let me = &mut *me;
        me.actions.recv.next_incoming(&mut me.store).map(|key| {
            let stream = &mut me.store.resolve(key);
            tracing::trace!(
                "next_incoming; id={:?}, state={:?}",
                stream.id,
                stream.state
            );
            // TODO: ideally, OpaqueStreamRefs::new would do this, but we're holding
            // the lock, so it can't.
            me.refs += 1;

            // Pending-accepted remotely-reset streams are counted.
            if stream.state.is_remote_reset() {
                me.counts.dec_num_remote_reset_streams();
            }

            StreamRef {
                opaque: OpaqueStreamRef::new(self.inner.clone(), stream),
                send_buffer: self.send_buffer.clone(),
            }
        })
    }

    pub fn send_pending_refusal<T>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        let mut me = self.inner.lock();
        let me = &mut *me;
        me.actions.recv.send_pending_refusal(cx, dst)
    }

    /// Takes the next frame to send on the live connection (see [`Control`]).
    pub fn take_control(&mut self) -> Option<ControlFrame> {
        self.inner.lock().control.pop_front()
    }

    /// Puts back a frame [`Self::take_control`] took but couldn't send yet.
    pub fn untake_control(&mut self, frame: ControlFrame) {
        self.inner.lock().control.push_front(frame);
    }

    /// A handle sending frames on this connection while it lives (see [`Control`]).
    pub fn control(&self) -> Control {
        Control(Arc::clone(&self.inner))
    }

    pub fn clear_expired_reset_streams(&mut self) {
        let mut me = self.inner.lock();
        let me = &mut *me;
        me.actions
            .recv
            .clear_expired_reset_streams(&mut me.store, &mut me.counts);
    }

    pub fn poll_complete<T>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        let mut me = self.inner.lock();
        me.poll_complete(&self.send_buffer, cx, dst)
    }

    pub fn apply_remote_settings(
        &mut self,
        frame: &frame::Settings,
        is_initial: bool,
    ) -> Result<(), Error> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        me.counts.apply_remote_settings(frame, is_initial);

        me.actions.send.apply_remote_settings(
            frame,
            send_buffer,
            &mut me.store,
            &mut me.counts,
            &mut me.actions.task,
        )
    }

    pub fn apply_local_settings(&mut self, frame: &frame::Settings) -> Result<(), Error> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        me.actions.recv.apply_local_settings(frame, &mut me.store)
    }

    pub fn send_request(
        &mut self,
        mut request: Request<()>,
        end_of_stream: bool,
        pending: Option<&OpaqueStreamRef>,
    ) -> Result<(StreamRef<B>, bool), SendError> {
        use http::Method;

        use super::stream::ContentLength;

        let protocol = request.extensions_mut().remove::<Protocol>();
        let order = request.extensions_mut().remove::<HeaderOrder>();
        let headers_frame = request.extensions_mut().remove::<HeadersFrameOptions>();

        // Clear before taking lock, incase extensions contain a StreamRef.
        request.extensions_mut().clear();

        // TODO: There is a hazard with assigning a stream ID before the
        // prioritize layer. If prioritization reorders new streams, this
        // implicitly closes the earlier stream IDs.
        //
        // See: hyperium/h2#11
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        me.actions.ensure_no_conn_error()?;
        me.actions.send.ensure_next_stream_id()?;

        // The `pending` argument is provided by the `Client`, and holds
        // a store `Key` of a `Stream` that may have been not been opened
        // yet.
        //
        // If that stream is still pending, the Client isn't allowed to
        // queue up another pending stream. They should use `poll_ready`.
        if let Some(stream) = pending {
            if me.store.resolve(stream.key).is_pending_open {
                return Err(UserError::Rejected.into());
            }
        }

        if me.counts.peer().is_server() {
            // Servers cannot open streams. PushPromise must first be reserved.
            return Err(UserError::UnexpectedFrameType.into());
        }

        let stream_id = me.actions.send.open()?;

        let mut stream = Stream::new(
            stream_id,
            me.actions.send.init_window_sz(),
            me.actions.recv.init_window_sz(),
        );
        stream
            .recv_flow
            .set_threshold(me.actions.recv.stream_threshold());

        if *request.method() == Method::HEAD {
            stream.content_length = ContentLength::Head;
        }

        // Priorities frame check before sending the request.
        if let Some(priorities) = &me.priorities {
            let next_id = priorities
                .max_stream_id()
                .next_id()
                .map_err(|_| SendError::User(UserError::OverflowedStreamId))?;

            if next_id > stream_id {
                return Err(SendError::User(UserError::OverflowedStreamId));
            }
        }

        // Convert the message
        let recorded = headers_frame
            .as_ref()
            .and_then(|frame| frame.recorded_stream_id);
        let renumber = |me: &Inner, priority: frame::Priority| match recorded {
            Some(recorded) => me.renumber_priority(priority, recorded, stream_id),
            None => priority,
        };
        let (pseudo_order, stream_dependency, leading, following) = match headers_frame {
            Some(frame) => (
                frame
                    .pseudo_order
                    .or_else(|| me.headers_pseudo_order.clone()),
                frame.priority.map(|priority| match recorded {
                    Some(recorded) => priority.depending_on(me.renumber(
                        priority.dependency_id().into(),
                        recorded,
                        stream_id,
                    )),
                    None => priority,
                }),
                frame.leading,
                frame.following,
            ),
            None => (
                me.headers_pseudo_order.clone(),
                me.headers_stream_dependency,
                Vec::new(),
                Vec::new(),
            ),
        };
        // The connection's first request carries the preface frames, numbered as the
        // first request recorded.
        let mut leading_frames = Vec::new();
        for frame in std::mem::take(&mut me.preface_frames) {
            leading_frames.push(match frame {
                PrefaceFrame::WindowUpdate(increment) => {
                    me.actions.recv.inc_connection_window(increment)?;
                    frame::Leading::WindowUpdate(frame::WindowUpdate::new(
                        StreamId::ZERO,
                        increment,
                    ))
                }
                PrefaceFrame::Priority(priority) => {
                    frame::Leading::Priority(renumber(&me, priority))
                }
                PrefaceFrame::Settings(params) => {
                    let mut settings = frame::Settings::default();
                    settings.set_wire(params);
                    frame::Leading::Settings(settings)
                }
                PrefaceFrame::Ping(payload) => frame::Leading::Ping(frame::Ping::new(payload)),
                PrefaceFrame::Unknown(f) => {
                    if f.payload.len() > frame::MAX_MAX_FRAME_SIZE as usize {
                        return Err(UserError::PayloadTooBig.into());
                    }
                    frame::Leading::Unknown(frame::Unknown::new(
                        f.kind,
                        f.flags,
                        f.stream_id,
                        f.payload,
                    ))
                }
            });
        }
        leading_frames.extend(
            leading
                .into_iter()
                .map(|priority| frame::Leading::Priority(renumber(&me, priority))),
        );
        let following: Vec<FollowingFrame> = following
            .into_iter()
            .map(|frame| match frame {
                FollowingFrame::Priority(priority) => {
                    FollowingFrame::Priority(renumber(&me, priority))
                }
                FollowingFrame::Unknown {
                    kind: PRIORITY_UPDATE,
                    flags,
                    on_stream: false,
                    payload,
                } => FollowingFrame::Unknown {
                    kind: PRIORITY_UPDATE,
                    flags,
                    on_stream: false,
                    payload: match recorded {
                        Some(recorded) => me.renumber_priority_update(payload, recorded, stream_id),
                        None => payload,
                    },
                },
                frame => frame,
            })
            .collect();
        if let Some(recorded) = recorded {
            if me.recorded_streams.len() == RECORDED_STREAMS {
                me.recorded_streams.pop_front();
            }
            me.recorded_streams.push_back((recorded, stream_id));
        }
        let mut headers = client::Peer::convert_send_message(
            stream_id,
            request,
            protocol,
            order,
            end_of_stream,
            pseudo_order,
            stream_dependency,
        )?;

        let following = following
            .into_iter()
            .map(|frame| match frame {
                FollowingFrame::WindowUpdate(increment) => {
                    stream
                        .recv_flow
                        .inc_recv_window(increment)
                        .map_err(|_| UserError::InvalidWindowUpdate)?;
                    Ok(frame::WindowUpdate::new(stream_id, increment).into())
                }
                FollowingFrame::Priority(priority) => Ok(priority.into()),
                FollowingFrame::Unknown {
                    kind,
                    flags,
                    on_stream,
                    payload,
                } => {
                    if payload.len() > frame::MAX_MAX_FRAME_SIZE as usize {
                        return Err(UserError::PayloadTooBig);
                    }
                    let stream_id = if on_stream { stream_id.into() } else { 0 };
                    Ok(frame::Unknown::new(kind, flags, stream_id, payload).into())
                }
            })
            .collect::<Result<Vec<Frame<B>>, UserError>>()?;

        if let Some(log) = &me.frame_log {
            stream.sent_headers = Some(HeadersFrame {
                stream_id: stream_id.into(),
                priority: headers.stream_dep().map(StreamDependency::to_ext),
                pseudo_order: headers.encoded_pseudo_order(),
                connection: log.clone(),
                received: me.received_frame_log.clone().unwrap_or_else(|| log.clone()),
            });
        }

        let mut stream = me.store.insert(stream.id, stream);

        // Leading frames go out encoded with the HEADERS, so nothing comes between, and a
        // second request queued before the connection runs still opens after the first.
        headers.set_leading(leading_frames);
        let sent = me.actions.send.send_priority_and_headers(
            me.priorities.clone(),
            headers,
            send_buffer,
            &mut stream,
            &mut me.counts,
            &mut me.actions.task,
        );

        // send_headers can return a UserError, if it does,
        // we should forget about this stream.
        if let Err(err) = sent {
            stream.unlink();
            stream.remove();
            return Err(err.into());
        }

        me.actions
            .send
            .queue_frames(following, send_buffer, &mut stream, &mut me.actions.task);

        // Given that the stream has been initialized, it should not be in the
        // closed state.
        debug_assert!(!stream.state.is_closed());

        // TODO: ideally, OpaqueStreamRefs::new would do this, but we're holding
        // the lock, so it can't.
        me.refs += 1;

        let is_full = me.counts.next_send_stream_will_reach_capacity();
        Ok((
            StreamRef {
                opaque: OpaqueStreamRef::new(self.inner.clone(), &mut stream),
                send_buffer: self.send_buffer.clone(),
            },
            is_full,
        ))
    }

    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.inner
            .lock()
            .actions
            .send
            .is_extended_connect_protocol_enabled()
    }

    pub fn current_max_send_streams(&self) -> usize {
        let me = self.inner.lock();
        me.counts.max_send_streams()
    }

    pub fn current_max_recv_streams(&self) -> usize {
        let me = self.inner.lock();
        me.counts.max_recv_streams()
    }
}

impl<B> DynStreams<'_, B> {
    pub fn is_buffer_empty(&self) -> bool {
        self.send_buffer.is_empty()
    }

    pub fn is_server(&self) -> bool {
        self.peer.is_server()
    }

    pub fn recv_headers(&mut self, frame: frame::Headers) -> Result<(), Error> {
        let mut me = self.inner.lock();

        me.recv_headers(self.peer, self.send_buffer, frame)
    }

    pub fn recv_data(&mut self, frame: frame::Data) -> Result<(), Error> {
        let mut me = self.inner.lock();
        me.recv_data(self.peer, self.send_buffer, frame)
    }

    pub fn recv_reset(&mut self, frame: frame::Reset) -> Result<(), Error> {
        let mut me = self.inner.lock();

        me.recv_reset(self.send_buffer, frame)
    }

    /// Notify all streams that a connection-level error happened.
    pub fn handle_error(&mut self, err: proto::Error) -> StreamId {
        let mut me = self.inner.lock();
        me.handle_error(self.send_buffer, err)
    }

    pub fn recv_go_away(&mut self, frame: &frame::GoAway) -> Result<(), Error> {
        let mut me = self.inner.lock();
        me.recv_go_away(self.send_buffer, frame)
    }

    pub fn last_processed_id(&self) -> StreamId {
        self.inner.lock().actions.recv.last_processed_id()
    }

    pub fn recv_window_update(&mut self, frame: frame::WindowUpdate) -> Result<(), Error> {
        let mut me = self.inner.lock();
        me.recv_window_update(self.send_buffer, frame)
    }

    pub fn recv_push_promise(&mut self, frame: frame::PushPromise) -> Result<(), Error> {
        let mut me = self.inner.lock();
        me.recv_push_promise(self.send_buffer, frame)
    }

    pub fn recv_eof(&mut self, clear_pending_accept: bool) -> Result<(), ()> {
        let mut me = self.inner.lock();
        me.recv_eof(self.send_buffer, clear_pending_accept)
    }

    pub fn send_reset(
        &mut self,
        id: StreamId,
        reason: Reason,
    ) -> Result<(), crate::proto::error::GoAway> {
        let mut me = self.inner.lock();
        me.send_reset(self.send_buffer, id, reason)
    }

    pub fn send_go_away(&mut self, last_processed_id: StreamId) {
        let mut me = self.inner.lock();
        me.actions.recv.go_away(last_processed_id);
    }
}

/// Sends frames of the caller's choosing on a live connection: queues them for the
/// connection's task, which sends them when it runs.
#[derive(Clone)]
pub(crate) struct Control(Arc<Mutex<Inner>>);

/// A frame queued by a [`Control`].
#[derive(Debug)]
pub(crate) enum ControlFrame {
    Settings(frame::Settings),
    Ping([u8; 8]),
    Priority(frame::Priority),
    Unknown(frame::Unknown),
}

impl<B> From<ControlFrame> for Frame<B> {
    fn from(frame: ControlFrame) -> Self {
        match frame {
            ControlFrame::Settings(settings) => settings.into(),
            ControlFrame::Ping(payload) => frame::Ping::new(payload).into(),
            ControlFrame::Priority(priority) => priority.into(),
            ControlFrame::Unknown(unknown) => unknown.into(),
        }
    }
}

impl fmt::Debug for Control {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Control").finish_non_exhaustive()
    }
}

impl Control {
    /// Queues a SETTINGS frame, whatever SETTINGS sent before await acknowledgement.
    pub(crate) fn send_settings(&self, frame: frame::Settings) {
        self.0.lock().queue_control(ControlFrame::Settings(frame));
    }

    /// Queues a PING carrying `payload`.
    pub(crate) fn send_ping(&self, payload: [u8; 8]) {
        self.0.lock().queue_control(ControlFrame::Ping(payload));
    }

    /// Queues `priority`, its streams numbered as the connection requests were recorded on
    /// numbered them, renumbered as [`Inner::recorded_stream`] does; a dependency on a
    /// stream this connection lacks is on the root instead, and a stream it lacks gets none.
    pub(crate) fn send_priority(&self, priority: frame::Priority) {
        let mut me = self.0.lock();
        let Some(stream_id) = me.recorded_stream(priority.stream_id().into()) else {
            return;
        };
        let dependency = priority.dependency();
        let dependency_id = me
            .recorded_stream(dependency.dependency_id().into())
            .unwrap_or(StreamId::ZERO);
        me.queue_control(ControlFrame::Priority(frame::Priority::new(
            stream_id,
            dependency.depending_on(dependency_id),
        )));
    }

    /// Queues a PRIORITY_UPDATE frame (RFC 9218) giving `stream_id`, numbered as the
    /// connection requests were recorded on numbered it, the priority `field_value`,
    /// renumbered as [`Inner::recorded_stream`] does; none for a stream this connection lacks.
    pub(crate) fn send_priority_update(&self, stream_id: u32, field_value: &[u8]) {
        let mut me = self.0.lock();
        let Some(stream_id) = me.recorded_stream(stream_id) else {
            return;
        };
        let mut payload = Vec::with_capacity(4 + field_value.len());
        payload.extend_from_slice(&u32::from(stream_id).to_be_bytes());
        payload.extend_from_slice(field_value);
        me.queue_control(ControlFrame::Unknown(frame::Unknown::new(
            PRIORITY_UPDATE,
            0,
            0,
            payload.into(),
        )));
    }

    /// Sets the unclaimed capacity the connection's WINDOW_UPDATEs and those of the
    /// streams opened from now on wait for; `None` is half the window.
    pub(crate) fn set_window_update_thresholds(
        &self,
        connection: Option<WindowSize>,
        stream: Option<WindowSize>,
    ) {
        let mut me = self.0.lock();
        me.actions
            .recv
            .set_window_update_thresholds(connection, stream);
        if let Some(task) = me.actions.task.take() {
            task.wake();
        }
    }
}

impl Inner {
    /// Queues `frame` for the connection's task, waking it.
    fn queue_control(&mut self, frame: ControlFrame) {
        self.control.push_back(frame);
        if let Some(task) = self.actions.task.take() {
            task.wake();
        }
    }

    /// The stream this connection uses for `id`, a stream as the connection requests were
    /// recorded on numbered it: that of the request recorded as `id` (see
    /// [`HeadersFrameOptions::recorded_stream_id`]), or `id` itself below the first such
    /// request's, a stream only PRIORITY frames name; `None` for a stream of another request.
    fn recorded_stream(&self, id: u32) -> Option<StreamId> {
        let (first, _) = self.recorded_streams.front()?;
        if id < *first {
            return Some(StreamId::from(id));
        }
        self.recorded_streams
            .iter()
            .rev()
            .find(|(recorded, _)| *recorded == id)
            .map(|(_, opened)| *opened)
    }

    /// The stream this connection uses for `id`, a stream as the connection a request was
    /// recorded on numbered it, where that request (`recorded`) is sent as `opened` (see
    /// [`HeadersFrameOptions::recorded_stream_id`]).
    fn renumber(&self, id: u32, recorded: u32, opened: StreamId) -> StreamId {
        if id == 0 {
            return StreamId::ZERO;
        }
        if id == recorded {
            return opened;
        }
        if id > recorded {
            return StreamId::from(
                (id - recorded).saturating_add(opened.into()) & u32::from(StreamId::MAX),
            );
        }
        let first = self
            .recorded_streams
            .front()
            .map_or(recorded, |(id, _)| *id);
        if id < first {
            return StreamId::from(id);
        }
        self.recorded_streams
            .iter()
            .rev()
            .find(|(recorded, _)| *recorded == id)
            .map_or(StreamId::ZERO, |(_, opened)| *opened)
    }

    /// `payload`, a PRIORITY_UPDATE frame's, with its prioritized stream renumbered (see
    /// [`Self::renumber`]).
    fn renumber_priority_update(&self, payload: Bytes, recorded: u32, opened: StreamId) -> Bytes {
        if payload.len() < 4 {
            return payload;
        }
        let mut field_value = payload;
        let id = field_value.get_u32() & u32::from(StreamId::MAX);
        let id = u32::from(self.renumber(id, recorded, opened));
        [&id.to_be_bytes()[..], &field_value[..]].concat().into()
    }

    /// `priority` with its stream and dependency renumbered (see [`Self::renumber`]).
    fn renumber_priority(
        &self,
        priority: frame::Priority,
        recorded: u32,
        opened: StreamId,
    ) -> frame::Priority {
        let dependency = priority.dependency();
        frame::Priority::new(
            self.renumber(priority.stream_id().into(), recorded, opened),
            dependency.depending_on(self.renumber(
                dependency.dependency_id().into(),
                recorded,
                opened,
            )),
        )
    }

    fn new(peer: peer::Dyn, config: Config) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Inner {
            counts: Counts::new(peer, &config),
            actions: Actions {
                recv: Recv::new(peer, &config),
                send: Send::new(&config),
                task: None,
                conn_error: None,
            },
            store: Store::new(),
            refs: 1,
            headers_stream_dependency: config.headers_stream_dependency,
            headers_pseudo_order: config.headers_pseudo_order,
            priorities: config.priorities,
            preface_frames: config.preface_frames,
            control: VecDeque::new(),
            frame_log: config.frame_log,
            received_frame_log: config.received_frame_log,
            recorded_streams: VecDeque::new(),
        }))
    }

    fn recv_headers<B>(
        &mut self,
        peer: peer::Dyn,
        send_buffer: &SendBuffer<B>,
        frame: frame::Headers,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        // The GOAWAY process has begun. All streams with a greater ID than
        // specified as part of GOAWAY should be ignored.
        if id > self.actions.recv.max_stream_id() {
            tracing::trace!(
                "id ({:?}) > max_stream_id ({:?}), ignoring HEADERS",
                id,
                self.actions.recv.max_stream_id()
            );
            return Ok(());
        }

        let key = match self.store.find_entry(id) {
            Entry::Occupied(e) => e.key(),
            Entry::Vacant(e) => {
                // Client: it's possible to send a request, and then send
                // a RST_STREAM while the response HEADERS were in transit.
                //
                // Server: we can't reset a stream before having received
                // the request headers, so don't allow.
                if !peer.is_server() {
                    // This may be response headers for a stream we've already
                    // forgotten about...
                    if self.actions.may_have_forgotten_stream(peer, id) {
                        tracing::debug!(
                            "recv_headers for old stream={:?}, sending STREAM_CLOSED",
                            id,
                        );
                        return Err(Error::library_reset(id, Reason::STREAM_CLOSED));
                    }
                }

                match self
                    .actions
                    .recv
                    .open(id, Open::Headers, &mut self.counts)?
                {
                    Some(stream_id) => {
                        let stream = Stream::new(
                            stream_id,
                            self.actions.send.init_window_sz(),
                            self.actions.recv.init_window_sz(),
                        );

                        e.insert(stream)
                    }
                    None => return Ok(()),
                }
            }
        };

        let stream = self.store.resolve(key);

        if stream.is_pending_open {
            proto_err!(conn: "recv_headers: received frame on idle stream {:?}", id);
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        if stream.state.is_local_error() {
            // Locally reset streams must ignore frames "for some time".
            // This is because the remote may have sent trailers before
            // receiving the RST_STREAM frame.
            tracing::trace!("recv_headers; ignoring trailers on {:?}", stream.id);
            return Ok(());
        }

        let actions = &mut self.actions;
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        self.counts.transition(stream, |counts, stream| {
           tracing::trace!(
                "recv_headers; stream={:?}; state={:?}",
                stream.id,
                stream.state
            );

            let res = if stream.state.is_recv_headers() {
                match actions.recv.recv_headers(frame, stream, counts) {
                    Ok(()) => Ok(()),
                    Err(RecvHeaderBlockError::Oversize(resp)) => {
                        if let Some(resp) = resp {
                            let sent = actions.send.send_headers(
                                resp, send_buffer, stream, counts, &mut actions.task);
                            debug_assert!(sent.is_ok(), "oversize response should not fail");

                            actions.send.schedule_implicit_reset(
                                stream,
                                Reason::PROTOCOL_ERROR,
                                counts,
                                &mut actions.task);

                            actions.recv.enqueue_reset_expiration(stream, counts);

                            Ok(())
                        } else {
                            Err(Error::library_reset(stream.id, Reason::PROTOCOL_ERROR))
                        }
                    },
                    Err(RecvHeaderBlockError::State(err)) => Err(err),
                }
            } else {
                if !frame.is_end_stream() {
                    // Receiving trailers that don't set EOS is a "malformed"
                    // message. Malformed messages are a stream error.
                    proto_err!(stream: "recv_headers: trailers frame was not EOS; stream={:?}", stream.id);
                    return Err(Error::library_reset(stream.id, Reason::PROTOCOL_ERROR));
                }

                actions.recv.recv_trailers(frame, stream)
            };

            actions.reset_on_recv_stream_err(send_buffer, stream, counts, res)
        })
    }

    fn recv_data<B>(
        &mut self,
        peer: peer::Dyn,
        send_buffer: &SendBuffer<B>,
        frame: frame::Data,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        let stream = match self.store.find_mut(&id) {
            Some(stream) => stream,
            None => {
                // The GOAWAY process has begun. All streams with a greater ID
                // than specified as part of GOAWAY should be ignored.
                if id > self.actions.recv.max_stream_id() {
                    tracing::trace!(
                        "id ({:?}) > max_stream_id ({:?}), ignoring DATA",
                        id,
                        self.actions.recv.max_stream_id()
                    );

                    // We still need to account for connection-level flow control.
                    let sz = frame.flow_controlled_len();
                    assert!(sz <= super::MAX_WINDOW_SIZE as usize);
                    let sz = sz as WindowSize;
                    self.actions.recv.ignore_data(sz)?;

                    return Ok(());
                }

                if self.actions.may_have_forgotten_stream(peer, id) {
                    tracing::debug!("recv_data for old stream={:?}, sending STREAM_CLOSED", id,);

                    let sz = frame.flow_controlled_len();
                    // This should have been enforced at the codec::FramedRead layer, so
                    // this is just a sanity check.
                    assert!(sz <= super::MAX_WINDOW_SIZE as usize);
                    let sz = sz as WindowSize;
                    self.actions.recv.ignore_data(sz)?;

                    return Err(Error::library_reset(id, Reason::STREAM_CLOSED));
                }

                proto_err!(conn: "recv_data: stream not found; id={:?}", id);
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }
        };

        let actions = &mut self.actions;
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        self.counts.transition(stream, |counts, stream| {
            let sz = frame.flow_controlled_len();
            let res = actions.recv.recv_data(frame, stream);

            // Any stream error after receiving a DATA frame means
            // we won't give the data to the user, and so they can't
            // release the capacity. We do it automatically.
            if let Err(Error::Reset(..)) = res {
                actions
                    .recv
                    .release_connection_capacity(sz as WindowSize, &mut None);
            }
            actions.reset_on_recv_stream_err(send_buffer, stream, counts, res)
        })
    }

    fn recv_reset<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: frame::Reset,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        if id.is_zero() {
            proto_err!(conn: "recv_reset: invalid stream ID 0");
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        // The GOAWAY process has begun. All streams with a greater ID than
        // specified as part of GOAWAY should be ignored.
        if id > self.actions.recv.max_stream_id() {
            tracing::trace!(
                "id ({:?}) > max_stream_id ({:?}), ignoring RST_STREAM",
                id,
                self.actions.recv.max_stream_id()
            );
            return Ok(());
        }

        let stream = match self.store.find_mut(&id) {
            Some(stream) => stream,
            None => {
                // TODO: Are there other error cases?
                self.actions
                    .ensure_not_idle(self.counts.peer(), id)
                    .map_err(Error::library_go_away)?;

                return Ok(());
            }
        };

        if stream.is_pending_open {
            proto_err!(conn: "recv_reset: received frame on idle stream {:?}", id);
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        let actions = &mut self.actions;

        self.counts.transition(stream, |counts, stream| {
            actions.recv.recv_reset(frame, stream, counts)?;
            actions.send.handle_error(send_buffer, stream, counts);
            assert!(stream.state.is_closed());
            Ok(())
        })
    }

    fn recv_window_update<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: frame::WindowUpdate,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        if id.is_zero() {
            self.actions
                .send
                .recv_connection_window_update(frame, &mut self.store, &mut self.counts)
                .map_err(Error::library_go_away)?;
        } else {
            // The remote may send window updates for streams that the local now
            // considers closed. It's ok...
            if let Some(mut stream) = self.store.find_mut(&id) {
                if stream.is_pending_open {
                    proto_err!(conn: "recv_window_update: received frame on idle stream {:?}", id);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }

                let res = self
                    .actions
                    .send
                    .recv_stream_window_update(
                        frame.size_increment(),
                        send_buffer,
                        &mut stream,
                        &mut self.counts,
                        &mut self.actions.task,
                    )
                    .map_err(|reason| Error::library_reset(id, reason));

                return self.actions.reset_on_recv_stream_err(
                    send_buffer,
                    &mut stream,
                    &mut self.counts,
                    res,
                );
            } else {
                self.actions
                    .ensure_not_idle(self.counts.peer(), id)
                    .map_err(Error::library_go_away)?;
            }
        }

        Ok(())
    }

    fn handle_error<B>(&mut self, send_buffer: &SendBuffer<B>, err: proto::Error) -> StreamId {
        let actions = &mut self.actions;
        let counts = &mut self.counts;
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        let last_processed_id = actions.recv.last_processed_id();

        self.store.for_each(|stream| {
            counts.transition(stream, |counts, stream| {
                actions.recv.handle_error(&err, &mut *stream);
                actions.send.handle_error(send_buffer, stream, counts);
            })
        });

        actions.conn_error = Some(err);

        last_processed_id
    }

    fn recv_go_away<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: &frame::GoAway,
    ) -> Result<(), Error> {
        let actions = &mut self.actions;
        let counts = &mut self.counts;
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        let last_stream_id = frame.last_stream_id();

        actions.send.recv_go_away(last_stream_id)?;

        let err = Error::remote_go_away(frame.debug_data().clone(), frame.reason());

        let peer = counts.peer();
        self.store.for_each(|stream| {
            if stream.id > last_stream_id && peer.is_local_init(stream.id) {
                counts.transition(stream, |counts, stream| {
                    actions.recv.handle_error(&err, &mut *stream);
                    actions.send.handle_error(send_buffer, stream, counts);
                })
            }
        });

        actions.conn_error = Some(err);

        Ok(())
    }

    fn recv_push_promise<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: frame::PushPromise,
    ) -> Result<(), Error> {
        let id = frame.stream_id();
        let promised_id = frame.promised_id();

        // First, ensure that the initiating stream is still in a valid state.
        let parent_key = match self.store.find_mut(&id) {
            Some(stream) => {
                // The GOAWAY process has begun. All streams with a greater ID
                // than specified as part of GOAWAY should be ignored.
                if id > self.actions.recv.max_stream_id() {
                    tracing::trace!(
                        "id ({:?}) > max_stream_id ({:?}), ignoring PUSH_PROMISE",
                        id,
                        self.actions.recv.max_stream_id()
                    );
                    return Ok(());
                }

                // The stream must be receive open
                if !stream.state.ensure_recv_open()? {
                    proto_err!(conn: "recv_push_promise: initiating stream is not opened");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }

                stream.key()
            }
            None => {
                proto_err!(conn: "recv_push_promise: initiating stream is in an invalid state");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }
        };

        // TODO: Streams in the reserved states do not count towards the concurrency
        // limit. However, it seems like there should be a cap otherwise this
        // could grow in memory indefinitely.

        // Ensure that we can reserve streams
        self.actions.recv.ensure_can_reserve()?;

        // Next, open the stream.
        //
        // If `None` is returned, then the stream is being refused. There is no
        // further work to be done.
        if self
            .actions
            .recv
            .open(promised_id, Open::PushPromise, &mut self.counts)?
            .is_none()
        {
            return Ok(());
        }

        // Try to handle the frame and create a corresponding key for the pushed stream
        // this requires a bit of indirection to make the borrow checker happy.
        let child_key: Option<store::Key> = {
            // Create state for the stream
            let stream = self.store.insert(promised_id, {
                Stream::new(
                    promised_id,
                    self.actions.send.init_window_sz(),
                    self.actions.recv.init_window_sz(),
                )
            });

            let actions = &mut self.actions;

            self.counts.transition(stream, |counts, stream| {
                let stream_valid = actions.recv.recv_push_promise(frame, stream);

                match stream_valid {
                    Ok(()) => Ok(Some(stream.key())),
                    _ => {
                        let mut send_buffer = send_buffer.inner.lock();
                        actions
                            .reset_on_recv_stream_err(
                                &mut *send_buffer,
                                stream,
                                counts,
                                stream_valid,
                            )
                            .map(|()| None)
                    }
                }
            })?
        };
        // If we're successful, push the headers and stream...
        if let Some(child) = child_key {
            let mut ppp = self.store[parent_key].pending_push_promises.take();
            ppp.push(&mut self.store.resolve(child));

            let parent = &mut self.store.resolve(parent_key);
            parent.pending_push_promises = ppp;
            parent.notify_push();
        };

        Ok(())
    }

    fn recv_eof<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        clear_pending_accept: bool,
    ) -> Result<(), ()> {
        let actions = &mut self.actions;
        let counts = &mut self.counts;
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        if actions.conn_error.is_none() {
            actions.conn_error = Some(
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed because of a broken pipe",
                )
                .into(),
            );
        }

        tracing::trace!("Streams::recv_eof");

        self.store.for_each(|stream| {
            counts.transition(stream, |counts, stream| {
                actions.recv.recv_eof(stream);

                // This handles resetting send state associated with the
                // stream
                actions.send.handle_error(send_buffer, stream, counts);
            })
        });

        actions.clear_queues(clear_pending_accept, &mut self.store, counts);
        Ok(())
    }

    fn poll_complete<T, B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        cx: &mut Context,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        // Send WINDOW_UPDATE frames first
        //
        // TODO: It would probably be better to interleave updates w/ data
        // frames.
        ready!(self
            .actions
            .recv
            .poll_complete(cx, &mut self.store, &mut self.counts, dst))?;

        // Send any other pending frames
        ready!(self.actions.send.poll_complete(
            cx,
            send_buffer,
            &mut self.store,
            &mut self.counts,
            dst
        ))?;

        // Nothing else to do, track the task
        self.actions.task = Some(cx.waker().clone());

        Poll::Ready(Ok(()))
    }

    fn send_reset<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        id: StreamId,
        reason: Reason,
    ) -> Result<(), crate::proto::error::GoAway> {
        let key = match self.store.find_entry(id) {
            Entry::Occupied(e) => e.key(),
            Entry::Vacant(e) => {
                // Resetting a stream we don't know about? That could be OK...
                //
                // 1. As a server, we just received a request, but that request was bad, so we're
                //    resetting before even accepting it. This is totally fine.
                //
                // 2. The remote may have sent us a frame on new stream that it's *not* supposed to
                //    have done, and thus, we don't know the stream. In that case, sending a reset
                //    will "open" the stream in our store. Maybe that should be a connection error
                //    instead? At least for now, we need to update what our vision of the next
                //    stream is.
                if self.counts.peer().is_local_init(id) {
                    // We normally would open this stream, so update our
                    // next-send-id record.
                    self.actions.send.maybe_reset_next_stream_id(id);
                } else {
                    // We normally would recv this stream, so update our
                    // next-recv-id record.
                    self.actions.recv.maybe_reset_next_stream_id(id);
                }

                let stream = Stream::new(id, 0, 0);

                e.insert(stream)
            }
        };

        let stream = self.store.resolve(key);
        let mut send_buffer = send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;
        self.actions.send_reset(
            stream,
            reason,
            Initiator::Library,
            &mut self.counts,
            send_buffer,
        )
    }
}

impl<B> Streams<B, client::Peer>
where
    B: Buf,
{
    pub fn poll_pending_open(
        &mut self,
        cx: &Context,
        pending: Option<&OpaqueStreamRef>,
    ) -> Poll<Result<(), crate::Error>> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        me.actions.ensure_no_conn_error()?;
        me.actions.send.ensure_next_stream_id()?;

        if let Some(pending) = pending {
            let mut stream = me.store.resolve(pending.key);
            tracing::trace!("poll_pending_open; stream = {:?}", stream.is_pending_open);
            if stream.is_pending_open {
                stream.wait_send(cx);
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<B, P> Streams<B, P>
where
    P: Peer,
{
    pub fn as_dyn(&self) -> DynStreams<'_, B> {
        let Self {
            inner,
            send_buffer,
            _p,
            ..
        } = self;
        DynStreams {
            inner,
            send_buffer,
            peer: P::r#dyn(),
        }
    }

    /// This function is safe to call multiple times.
    ///
    /// A `Result` is returned to avoid panicking if the mutex is poisoned.
    pub fn recv_eof(&mut self, clear_pending_accept: bool) -> Result<(), ()> {
        self.as_dyn().recv_eof(clear_pending_accept)
    }

    pub(crate) fn max_send_streams(&self) -> usize {
        self.inner.lock().counts.max_send_streams()
    }

    pub(crate) fn max_recv_streams(&self) -> usize {
        self.inner.lock().counts.max_recv_streams()
    }

    #[cfg(feature = "unstable")]
    pub fn num_active_streams(&self) -> usize {
        let me = self.inner.lock();
        me.store.num_active_streams()
    }

    pub fn has_streams(&self) -> bool {
        let me = self.inner.lock();
        me.counts.has_streams()
    }

    pub fn has_streams_or_other_references(&self) -> bool {
        let me = self.inner.lock();
        me.counts.has_streams() || me.refs > 1
    }

    #[cfg(feature = "unstable")]
    pub fn num_wired_streams(&self) -> usize {
        let me = self.inner.lock();
        me.store.num_wired_streams()
    }
}

// no derive because we don't need B and P to be Clone.
impl<B, P> Clone for Streams<B, P>
where
    P: Peer,
{
    fn clone(&self) -> Self {
        self.inner.lock().refs += 1;
        Streams {
            inner: self.inner.clone(),
            send_buffer: self.send_buffer.clone(),
            _p: ::std::marker::PhantomData,
        }
    }
}

impl<B, P> Drop for Streams<B, P>
where
    P: Peer,
{
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        inner.refs -= 1;
        if inner.refs == 1 {
            if let Some(task) = inner.actions.task.take() {
                task.wake();
            }
        }
    }
}

// ===== impl StreamRef =====

impl<B> StreamRef<B> {
    pub fn send_data(&mut self, data: B, end_stream: bool) -> Result<(), UserError>
    where
        B: Buf,
    {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            // Create the data frame
            let mut frame = frame::Data::new(stream.id, data);
            frame.set_end_stream(end_stream);

            // Send the data frame
            actions
                .send
                .send_data(frame, send_buffer, stream, counts, &mut actions.task)
        })
    }

    pub fn send_trailers(
        &mut self,
        trailers: HeaderMap,
        order: HeaderOrder,
    ) -> Result<(), UserError> {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            // Create the trailers frame
            let mut frame = frame::Headers::trailers(stream.id, trailers);
            frame.set_header_order(order);

            // Send the trailers frame
            actions
                .send
                .send_trailers(frame, send_buffer, stream, counts, &mut actions.task)
        })
    }

    pub fn send_reset(&mut self, reason: Reason) {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        match me
            .actions
            .send_reset(stream, reason, Initiator::User, &mut me.counts, send_buffer)
        {
            Ok(()) => (),
            Err(crate::proto::error::GoAway { .. }) => {
                // this should never happen, because Initiator::User resets do
                // not count toward the local limit.
                // we could perhaps make this state impossible, if we made the
                // initiator argument a generic, and so this could return
                // Infallible instead of an impossible GoAway, but oh well.
                unreachable!("Initiator::User should not error sending reset");
            }
        }
    }

    pub fn send_informational_headers(&mut self, frame: frame::Headers) -> Result<(), UserError> {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            // For informational responses (1xx), we need to send headers without
            // changing the stream state. This allows multiple informational responses
            // to be sent before the final response.

            // Validate that this is actually an informational response
            debug_assert!(
                frame.is_informational(),
                "Frame must be informational after conversion from informational response"
            );

            // Ensure the frame is not marked as end_stream for informational responses
            if frame.is_end_stream() {
                return Err(UserError::UnexpectedFrameType);
            }

            // Send the interim informational headers directly to the buffer without state changes
            // This bypasses the normal send_headers flow that would transition the stream state
            actions.send.send_interim_informational_headers(
                frame,
                send_buffer,
                stream,
                counts,
                &mut actions.task,
            )
        })
    }

    pub fn send_response(
        &mut self,
        mut response: Response<()>,
        end_of_stream: bool,
    ) -> Result<(), UserError> {
        let order = response.extensions_mut().remove::<HeaderOrder>();
        // Clear before taking lock, incase extensions contain a StreamRef.
        response.extensions_mut().clear();
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            let frame =
                server::Peer::convert_send_message(stream.id, response, order, end_of_stream);

            actions
                .send
                .send_headers(frame, send_buffer, stream, counts, &mut actions.task)
        })
    }

    pub fn send_push_promise(
        &mut self,
        mut request: Request<()>,
    ) -> Result<StreamRef<B>, UserError> {
        // Clear before taking lock, incase extensions contain a StreamRef.
        request.extensions_mut().clear();
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let mut send_buffer = self.send_buffer.inner.lock();
        let send_buffer = &mut *send_buffer;

        let actions = &mut me.actions;
        let promised_id = actions.send.reserve_local()?;

        let child_key = {
            let mut child_stream = me.store.insert(
                promised_id,
                Stream::new(
                    promised_id,
                    actions.send.init_window_sz(),
                    actions.recv.init_window_sz(),
                ),
            );
            child_stream.state.reserve_local()?;
            child_stream.is_pending_push = true;
            child_stream.key()
        };

        let pushed = {
            let mut stream = me.store.resolve(self.opaque.key);

            let frame = crate::server::Peer::convert_push_message(stream.id, promised_id, request)?;

            actions
                .send
                .send_push_promise(frame, send_buffer, &mut stream, &mut actions.task)
        };

        if let Err(err) = pushed {
            let mut child_stream = me.store.resolve(child_key);
            child_stream.unlink();
            child_stream.remove();
            return Err(err);
        }

        me.refs += 1;
        let opaque =
            OpaqueStreamRef::new(self.opaque.inner.clone(), &mut me.store.resolve(child_key));

        Ok(StreamRef {
            opaque,
            send_buffer: self.send_buffer.clone(),
        })
    }

    /// Called by the server after the stream is accepted. Given that clients
    /// initialize streams by sending HEADERS, the request will always be
    /// available.
    ///
    /// # Panics
    ///
    /// This function panics if the request isn't present.
    pub fn take_request(&self) -> Request<()> {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);
        me.actions.recv.take_request(&mut stream)
    }

    /// Called by a client to see if the current stream is pending open
    pub fn is_pending_open(&self) -> bool {
        let mut me = self.opaque.inner.lock();
        me.store.resolve(self.opaque.key).is_pending_open
    }

    /// Request capacity to send data
    pub fn reserve_capacity(&mut self, capacity: WindowSize) {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions
            .send
            .reserve_capacity(capacity, &mut stream, &mut me.counts)
    }

    /// Returns the stream's current send capacity.
    pub fn capacity(&self) -> WindowSize {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions.send.capacity(&mut stream)
    }

    /// Request to be notified when the stream's capacity increases
    pub fn poll_capacity(&mut self, cx: &Context) -> Poll<Option<Result<WindowSize, UserError>>> {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions.send.poll_capacity(cx, &mut stream)
    }

    /// Request to be notified for if a `RST_STREAM` is received for this stream.
    pub(crate) fn poll_reset(
        &mut self,
        cx: &Context,
        mode: proto::PollReset,
    ) -> Poll<Result<Reason, crate::Error>> {
        let mut me = self.opaque.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions.send.poll_reset(cx, &mut stream, mode)
    }

    pub fn clone_to_opaque(&self) -> OpaqueStreamRef {
        self.opaque.clone()
    }

    pub fn stream_id(&self) -> StreamId {
        self.opaque.stream_id()
    }
}

impl<B> Clone for StreamRef<B> {
    fn clone(&self) -> Self {
        StreamRef {
            opaque: self.opaque.clone(),
            send_buffer: self.send_buffer.clone(),
        }
    }
}

// ===== impl OpaqueStreamRef =====

impl OpaqueStreamRef {
    fn new(inner: Arc<Mutex<Inner>>, stream: &mut store::Ptr) -> OpaqueStreamRef {
        stream.ref_inc();
        OpaqueStreamRef {
            inner,
            key: stream.key(),
        }
    }
    /// Called by a client to check for a received response.
    pub fn poll_response(&mut self, cx: &Context) -> Poll<Result<Response<()>, proto::Error>> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions
            .recv
            .poll_response(cx, &mut stream)
            .map_ok(|mut response| {
                if let Some(sent) = stream.sent_headers.take() {
                    response.extensions_mut().insert(sent);
                }
                response
            })
    }

    /// Called by a client to check for informational responses (1xx status codes)
    pub fn poll_informational(
        &mut self,
        cx: &Context,
    ) -> Poll<Option<Result<Response<()>, proto::Error>>> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions.recv.poll_informational(cx, &mut stream)
    }
    /// Called by a client to check for a pushed request.
    pub fn poll_pushed(
        &mut self,
        cx: &Context,
    ) -> Poll<Option<Result<(Request<()>, OpaqueStreamRef), proto::Error>>> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);
        me.actions
            .recv
            .poll_pushed(cx, &mut stream)
            .map_ok(|(h, key)| {
                me.refs += 1;
                let opaque_ref =
                    OpaqueStreamRef::new(self.inner.clone(), &mut me.store.resolve(key));
                (h, opaque_ref)
            })
    }

    pub fn is_end_stream(&self) -> bool {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let stream = me.store.resolve(self.key);

        me.actions.recv.is_end_stream(&stream)
    }

    pub fn poll_data(&mut self, cx: &Context) -> Poll<Option<Result<Bytes, proto::Error>>> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions.recv.poll_data(cx, &mut stream)
    }

    pub fn poll_trailers(
        &mut self,
        cx: &Context,
    ) -> Poll<Option<Result<(HeaderMap, HeaderOrder), proto::Error>>> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions.recv.poll_trailers(cx, &mut stream)
    }

    pub(crate) fn available_recv_capacity(&self) -> isize {
        let me = self.inner.lock();
        let me = &*me;

        let stream = &me.store[self.key];
        stream.recv_flow.available().into()
    }

    pub(crate) fn used_recv_capacity(&self) -> WindowSize {
        let me = self.inner.lock();
        let me = &*me;

        let stream = &me.store[self.key];
        stream.in_flight_recv_data
    }

    /// Releases recv capacity back to the peer. This may result in sending
    /// WINDOW_UPDATE frames on both the stream and connection.
    pub fn release_capacity(&mut self, capacity: WindowSize) -> Result<(), UserError> {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions
            .recv
            .release_capacity(capacity, &mut stream, &mut me.actions.task)
    }

    /// Clear the receive queue and set the status to no longer receive data frames.
    pub(crate) fn clear_recv_buffer(&mut self) {
        let mut me = self.inner.lock();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);
        stream.is_recv = false;
        me.actions.recv.clear_recv_buffer(&mut stream);
    }

    pub fn stream_id(&self) -> StreamId {
        self.inner.lock().store[self.key].id
    }
}

impl fmt::Debug for OpaqueStreamRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "parking_lot")]
        let lock_result = self.inner.try_lock();
        #[cfg(not(feature = "parking_lot"))]
        let lock_result = self.inner.try_lock().ok();

        match lock_result {
            Some(me) => {
                let stream = &me.store[self.key];
                fmt.debug_struct("OpaqueStreamRef")
                    .field("stream_id", &stream.id)
                    .field("ref_count", &stream.ref_count)
                    .finish()
            }
            None => fmt
                .debug_struct("OpaqueStreamRef")
                .field("inner", &"<Locked>")
                .finish(),
        }
    }
}

impl Clone for OpaqueStreamRef {
    fn clone(&self) -> Self {
        // Increment the ref count
        let mut inner = self.inner.lock();
        inner.store.resolve(self.key).ref_inc();
        inner.refs += 1;

        OpaqueStreamRef {
            inner: self.inner.clone(),
            key: self.key,
        }
    }
}

impl Drop for OpaqueStreamRef {
    fn drop(&mut self) {
        drop_stream_ref(&self.inner, self.key);
    }
}

// TODO: Move back in fn above
fn drop_stream_ref(inner: &Mutex<Inner>, key: store::Key) {
    let mut me = inner.lock();

    let me = &mut *me;
    me.refs -= 1;
    let mut stream = me.store.resolve(key);

    tracing::trace!("drop_stream_ref; stream={:?}", stream);

    // decrement the stream's ref count by 1.
    stream.ref_dec();

    let actions = &mut me.actions;

    // If the stream is not referenced and it is already
    // closed (does not have to go through logic below
    // of canceling the stream), we should notify the task
    // (connection) so that it can close properly
    if stream.ref_count == 0 && stream.is_closed() {
        if let Some(task) = actions.task.take() {
            task.wake();
        }
    }

    me.counts.transition(stream, |counts, stream| {
        maybe_cancel(stream, actions, counts);

        if stream.ref_count == 0 {
            // Release any recv window back to connection, no one can access
            // it anymore.
            actions
                .recv
                .release_closed_capacity(stream, &mut actions.task);

            // We won't be able to reach our push promises anymore
            let mut ppp = stream.pending_push_promises.take();
            while let Some(promise) = ppp.pop(stream.store_mut()) {
                counts.transition(promise, |counts, stream| {
                    maybe_cancel(stream, actions, counts);
                });
            }
        }
    });
}

fn maybe_cancel(stream: &mut store::Ptr, actions: &mut Actions, counts: &mut Counts) {
    if stream.is_canceled_interest() {
        // Server is allowed to early respond without fully consuming the client input stream
        // But per the RFC, must send a RST_STREAM(NO_ERROR) in such cases. https://www.rfc-editor.org/rfc/rfc7540#section-8.1
        // Some other http2 implementation may interpret other error code as fatal if not respected (i.e: nginx https://trac.nginx.org/nginx/ticket/2376)
        let reason = if counts.peer().is_server()
            && stream.state.is_send_closed()
            && stream.state.is_recv_streaming()
        {
            Reason::NO_ERROR
        } else {
            Reason::CANCEL
        };

        actions
            .send
            .schedule_implicit_reset(stream, reason, counts, &mut actions.task);
        actions.recv.enqueue_reset_expiration(stream, counts);
    }
}

// ===== impl SendBuffer =====

impl<B> SendBuffer<B> {
    fn new() -> Self {
        let inner = Mutex::new(Buffer::new());
        SendBuffer { inner }
    }

    pub fn is_empty(&self) -> bool {
        let buf = self.inner.lock();
        buf.is_empty()
    }
}

// ===== impl Actions =====

impl Actions {
    fn send_reset<B>(
        &mut self,
        stream: store::Ptr,
        reason: Reason,
        initiator: Initiator,
        counts: &mut Counts,
        send_buffer: &mut Buffer<Frame<B>>,
    ) -> Result<(), crate::proto::error::GoAway> {
        counts.transition(stream, |counts, stream| {
            if initiator.is_library() {
                if counts.can_inc_num_local_error_resets() {
                    counts.inc_num_local_error_resets();
                } else {
                    tracing::warn!(
                        "locally-reset streams reached limit ({:?})",
                        counts.max_local_error_resets().unwrap(),
                    );
                    return Err(crate::proto::error::GoAway {
                        reason: Reason::ENHANCE_YOUR_CALM,
                        debug_data: "too_many_internal_resets".into(),
                    });
                }
            }

            self.send.send_reset(
                reason,
                initiator,
                send_buffer,
                stream,
                counts,
                &mut self.task,
            );
            self.recv.enqueue_reset_expiration(stream, counts);
            // if a RecvStream is parked, ensure it's notified
            stream.notify_recv();

            Ok(())
        })
    }

    fn reset_on_recv_stream_err<B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        stream: &mut store::Ptr,
        counts: &mut Counts,
        res: Result<(), Error>,
    ) -> Result<(), Error> {
        if let Err(Error::Reset(stream_id, reason, initiator)) = res {
            debug_assert_eq!(stream_id, stream.id);

            if counts.can_inc_num_local_error_resets() {
                counts.inc_num_local_error_resets();

                // Reset the stream.
                self.send
                    .send_reset(reason, initiator, buffer, stream, counts, &mut self.task);
                self.recv.enqueue_reset_expiration(stream, counts);
                // if a RecvStream is parked, ensure it's notified
                stream.notify_recv();
                Ok(())
            } else {
                tracing::warn!(
                    "reset_on_recv_stream_err; locally-reset streams reached limit ({:?})",
                    counts.max_local_error_resets().unwrap(),
                );
                Err(Error::library_go_away_data(
                    Reason::ENHANCE_YOUR_CALM,
                    "too_many_internal_resets",
                ))
            }
        } else {
            res
        }
    }

    fn ensure_not_idle(&mut self, peer: peer::Dyn, id: StreamId) -> Result<(), Reason> {
        if peer.is_local_init(id) {
            self.send.ensure_not_idle(id)
        } else {
            self.recv.ensure_not_idle(id)
        }
    }

    fn ensure_no_conn_error(&self) -> Result<(), proto::Error> {
        if let Some(ref err) = self.conn_error {
            Err(err.clone())
        } else {
            Ok(())
        }
    }

    /// Check if we possibly could have processed and since forgotten this stream.
    ///
    /// If we send a RST_STREAM for a stream, we will eventually "forget" about
    /// the stream to free up memory. It's possible that the remote peer had
    /// frames in-flight, and by the time we receive them, our own state is
    /// gone. We *could* tear everything down by sending a GOAWAY, but it
    /// is more likely to be latency/memory constraints that caused this,
    /// and not a bad actor. So be less catastrophic, the spec allows
    /// us to send another RST_STREAM of STREAM_CLOSED.
    fn may_have_forgotten_stream(&self, peer: peer::Dyn, id: StreamId) -> bool {
        if id.is_zero() {
            return false;
        }
        if peer.is_local_init(id) {
            self.send.may_have_created_stream(id)
        } else {
            self.recv.may_have_created_stream(id)
        }
    }

    fn clear_queues(&mut self, clear_pending_accept: bool, store: &mut Store, counts: &mut Counts) {
        self.recv.clear_queues(clear_pending_accept, store, counts);
        self.send.clear_queues(store, counts);
    }
}
