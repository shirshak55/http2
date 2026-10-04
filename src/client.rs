//! Client implementation of the HTTP/2 protocol.
//!
//! # Getting started
//!
//! Running an HTTP/2 client requires the caller to establish the underlying
//! connection as well as get the connection to a state that is ready to begin
//! the HTTP/2 handshake. See [here](../index.html#handshake) for more
//! details.
//!
//! This could be as basic as using Tokio's [`TcpStream`] to connect to a remote
//! host, but usually it means using either ALPN or HTTP/1.1 protocol upgrades.
//!
//! Once a connection is obtained, it is passed to [`handshake`], which will
//! begin the [HTTP/2 handshake]. This returns a future that completes once
//! the handshake process is performed and HTTP/2 streams may be initialized.
//!
//! [`handshake`] uses default configuration values. There are a number of
//! settings that can be changed by using [`Builder`] instead.
//!
//! Once the handshake future completes, the caller is provided with a
//! [`Connection`] instance and a [`SendRequest`] instance. The [`Connection`]
//! instance is used to drive the connection (see [Managing the connection]).
//! The [`SendRequest`] instance is used to initialize new streams (see [Making
//! requests]).
//!
//! # Making requests
//!
//! Requests are made using the [`SendRequest`] handle provided by the handshake
//! future. Once a request is submitted, an HTTP/2 stream is initialized and
//! the request is sent to the server.
//!
//! A request body and request trailers are sent using [`SendRequest`] and the
//! server's response is returned once the [`ResponseFuture`] future completes.
//! Both the [`SendStream`] and [`ResponseFuture`] instances are returned by
//! [`SendRequest::send_request`] and are tied to the HTTP/2 stream
//! initialized by the sent request.
//!
//! The [`SendRequest::poll_ready`] function returns `Ready` when a new HTTP/2
//! stream can be created, i.e. as long as the current number of active streams
//! is below [`MAX_CONCURRENT_STREAMS`]. If a new stream cannot be created, the
//! caller will be notified once an existing stream closes, freeing capacity for
//! the caller.  The caller should use [`SendRequest::poll_ready`] to check for
//! capacity before sending a request to the server.
//!
//! [`SendRequest`] enforces the [`MAX_CONCURRENT_STREAMS`] setting. The user
//! must not send a request if `poll_ready` does not return `Ready`. Attempting
//! to do so will result in an [`Error`] being returned.
//!
//! # Managing the connection
//!
//! The [`Connection`] instance is used to manage connection state. The caller
//! is required to call [`Connection::poll`] in order to advance state.
//! [`SendRequest::send_request`] and other functions have no effect unless
//! [`Connection::poll`] is called.
//!
//! The [`Connection`] instance should only be dropped once [`Connection::poll`]
//! returns `Ready`. At this point, the underlying socket has been closed and no
//! further work needs to be done.
//!
//! The easiest way to ensure that the [`Connection`] instance gets polled is to
//! submit the [`Connection`] instance to an [executor]. The executor will then
//! manage polling the connection until the connection is complete.
//! Alternatively, the caller can call `poll` manually.
//!
//! # Example
//!
//! ```rust, no_run
//!
//! use http2::client;
//!
//! use http::{Request, Method};
//! use std::error::Error;
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! pub async fn main() -> Result<(), Box<dyn Error>> {
//!     // Establish TCP connection to the server.
//!     let tcp = TcpStream::connect("127.0.0.1:5928").await?;
//!     let (http2, connection) = client::handshake(tcp).await?;
//!     tokio::spawn(async move {
//!         connection.await.unwrap();
//!     });
//!
//!     let mut http2 = http2.ready().await?;
//!     // Prepare the HTTP request to send to the server.
//!     let request = Request::builder()
//!                     .method(Method::GET)
//!                     .uri("https://www.example.com/")
//!                     .body(())
//!                     .unwrap();
//!
//!     // Send the request. The second tuple item allows the caller
//!     // to stream a request body.
//!     let (response, _) = http2.send_request(request, true).unwrap();
//!
//!     let (head, mut body) = response.await?.into_parts();
//!
//!     println!("Received response: {:?}", head);
//!
//!     // The `flow_control` handle allows the caller to manage
//!     // flow control.
//!     //
//!     // Whenever data is received, the caller is responsible for
//!     // releasing capacity back to the server once it has freed
//!     // the data from memory.
//!     let mut flow_control = body.flow_control().clone();
//!
//!     while let Some(chunk) = body.data().await {
//!         let chunk = chunk?;
//!         println!("RX: {:?}", chunk);
//!
//!         // Let the server send more data.
//!         let _ = flow_control.release_capacity(chunk.len());
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! [`TcpStream`]: https://docs.rs/tokio-core/0.1/tokio_core/net/struct.TcpStream.html
//! [`handshake`]: fn.handshake.html
//! [executor]: https://docs.rs/futures/0.1/futures/future/trait.Executor.html
//! [`SendRequest`]: struct.SendRequest.html
//! [`SendStream`]: ../struct.SendStream.html
//! [Making requests]: #making-requests
//! [Managing the connection]: #managing-the-connection
//! [`Connection`]: struct.Connection.html
//! [`Connection::poll`]: struct.Connection.html#method.poll
//! [`SendRequest::send_request`]: struct.SendRequest.html#method.send_request
//! [`MAX_CONCURRENT_STREAMS`]: http://httpwg.org/specs/rfc7540.html#SettingValues
//! [`SendRequest`]: struct.SendRequest.html
//! [`ResponseFuture`]: struct.ResponseFuture.html
//! [`SendRequest::poll_ready`]: struct.SendRequest.html#method.poll_ready
//! [HTTP/2 handshake]: http://httpwg.org/specs/rfc7540.html#ConnectionHeader
//! [`Builder`]: struct.Builder.html
//! [`Error`]: ../struct.Error.html

use crate::codec::{Codec, SendError, UserError};
use crate::ext::{FrameLog, HeaderOrder, LoggedFrame, PrefaceFrame, Protocol, ReceivedPreface};
#[cfg(feature = "unstable")]
use crate::frame::ExperimentalSettings;
use crate::frame::{
    Headers, Priorities, Priority, Pseudo, PseudoOrder, Reason, Settings, SettingsOrder,
    StreamDependency, StreamId, MAX_MAX_FRAME_SIZE,
};
use crate::proto::{self, Error};
use crate::{tracing, FlowControl, PingPong, RecvStream, SendStream};

#[cfg(feature = "tracing")]
use ::tracing::Instrument;
use bytes::{Buf, Bytes};
use http::{uri, HeaderMap, Method, Request, Response, Version};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Initializes new HTTP/2 streams on a connection by sending a request.
///
/// This type does no work itself. Instead, it is a handle to the inner
/// connection state held by [`Connection`]. If the associated connection
/// instance is dropped, all `SendRequest` functions will return [`Error`].
///
/// [`SendRequest`] instances are able to move to and operate on separate tasks
/// / threads than their associated [`Connection`] instance. Internally, there
/// is a buffer used to stage requests before they get written to the
/// connection. There is no guarantee that requests get written to the
/// connection in FIFO order as HTTP/2 prioritization logic can play a role.
///
/// [`SendRequest`] implements [`Clone`], enabling the creation of many
/// instances that are backed by a single connection.
///
/// See [module] level documentation for more details.
///
/// [module]: index.html
/// [`Connection`]: struct.Connection.html
/// [`Clone`]: https://doc.rust-lang.org/std/clone/trait.Clone.html
/// [`Error`]: ../struct.Error.html
pub struct SendRequest<B: Buf> {
    inner: proto::Streams<B, Peer>,
    pending: Option<proto::OpaqueStreamRef>,
    preface: ReceivedPreface,
}

/// Sends frames of the caller's choosing on a live HTTP/2 client connection (see
/// [`SendRequest::control`]); the connection's task sends them in order when their turn
/// comes, and they end with the connection. Also tells the peer's connection preface.
///
/// A frame goes out when the connection next runs, unless the handle follows a request
/// (see [`Self::after_request`]), and right ahead of the HEADERS of any request carrying a
/// [recorded stream id](crate::ext::HeadersFrameOptions::recorded_stream_id) past the one
/// it follows that is sent before it goes out.
#[derive(Clone, Debug)]
pub struct Control {
    inner: proto::Control,
    preface: ReceivedPreface,
}

impl Control {
    /// A handle whose frames follow the request recorded as `recorded` (see
    /// [`recorded_stream_id`](crate::ext::HeadersFrameOptions::recorded_stream_id)): each
    /// goes out once that request's HEADERS did, or once [`Self::release_request`] tells
    /// it won't be sent here.
    pub fn after_request(&self, recorded: u32) -> Self {
        Control {
            inner: self.inner.after_request(recorded),
            preface: self.preface.clone(),
        }
    }

    /// Sends a SETTINGS frame of exactly `params`, `(identifier, value)` in order, whatever
    /// SETTINGS sent before await acknowledgement (RFC 9113 §6.5.3); the known parameters
    /// apply to the connection when the peer acknowledges it, as its own do.
    pub fn send_settings(&self, params: impl IntoIterator<Item = (u16, u32)>) {
        let mut frame = Settings::default();
        frame.set_wire(params.into_iter().collect());
        self.inner.send_settings(frame);
    }

    /// Sends a PING carrying `payload`, whose acknowledgement goes to the caller relaying the
    /// frames past the peer's preface (see [`Self::relay_received`]), if any.
    pub fn send_ping(&self, payload: [u8; 8]) {
        self.inner.send_ping(payload);
    }

    /// Hands over the frames the peer sends past its connection preface (see
    /// [`Self::received_preface`]) from now on, for a caller relaying them to another peer:
    /// its SETTINGS, PINGs, WINDOW_UPDATEs and frames of types HTTP/2 doesn't define, as
    /// [`LoggedFrame`]s in the order received, a request's stream numbered as it was
    /// recorded (see
    /// [`recorded_stream_id`](crate::ext::HeadersFrameOptions::recorded_stream_id)); a
    /// WINDOW_UPDATE for a stream of no such request isn't handed over. The connection
    /// then acknowledges neither those SETTINGS nor those PINGs itself:
    /// [`Self::send_settings_ack`] and [`Self::send_ping_ack`] relay the other peer's
    /// acknowledgements. Once the receiver is dropped, it acknowledges them itself again.
    /// The peer's acknowledgements of the SETTINGS and PINGs sent for the other peer
    /// ([`Self::send_settings`], [`Self::send_ping`]) come too, in their place among
    /// those frames, those received before the first call first; not those of the
    /// connection's own preface, nor of the preface frames a request carried.
    pub fn relay_received(&self) -> tokio::sync::mpsc::UnboundedReceiver<LoggedFrame> {
        self.inner.relay_received(self.preface.clone())
    }

    /// Acknowledges the earliest relayed SETTINGS frame not yet acknowledged (see
    /// [`Self::relay_received`]).
    pub fn send_settings_ack(&self) {
        self.inner.send_settings_ack();
    }

    /// Acknowledges a relayed PING carrying `payload` (see [`Self::relay_received`]).
    pub fn send_ping_ack(&self, payload: [u8; 8]) {
        self.inner.send_ping_ack(payload);
    }

    /// Sends a frame of a type HTTP/2 doesn't define, of `kind`, `flags` and `payload`, on
    /// the connection (`stream_id` 0) or a stream numbered as [`Self::send_priority`]'s
    /// streams are; not at all for a request this connection didn't send.
    ///
    /// # Panics
    ///
    /// This function panics if `payload` is longer than a frame can carry (2^24 - 1
    /// octets).
    pub fn send_unknown(&self, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        assert!(payload.len() <= MAX_MAX_FRAME_SIZE as usize);
        self.inner
            .send_unknown(kind, flags, stream_id, Bytes::copy_from_slice(payload));
    }

    /// Makes the request recorded as `recorded` (see
    /// [`recorded_stream_id`](crate::ext::HeadersFrameOptions::recorded_stream_id)), if sent
    /// here, reset with `reason` should it be dropped before it ends (rather than CANCEL) or
    /// reset (as [`SendStream::send_reset`] does, rather than its reason): as the client it
    /// is relayed from reset it.
    pub fn cancel_with(&self, recorded: u32, reason: Reason) {
        self.inner.cancel_with(recorded, reason);
    }

    /// Sends `priority`, a PRIORITY frame numbered as the connection requests were recorded
    /// on numbered streams (see
    /// [`recorded_stream_id`](crate::ext::HeadersFrameOptions::recorded_stream_id)), as this
    /// connection numbers them when it goes out: a stream below the first recorded
    /// request's as is, one past the latest recorded request's as far past the stream that
    /// request went out on, a dependency on a request this connection didn't send on the
    /// root, and not at all for such a request.
    pub fn send_priority(&self, priority: Priority) {
        self.inner.send_priority(priority);
    }

    /// Sends a PRIORITY_UPDATE frame (RFC 9218) giving `stream_id`, numbered as
    /// [`Self::send_priority`]'s streams are, the priority `field_value`; not at all for a
    /// request this connection didn't send.
    pub fn send_priority_update(&self, stream_id: u32, field_value: &[u8]) {
        self.inner.send_priority_update(stream_id, field_value);
    }

    /// Sends `frames` right before the next request's HEADERS frame, encoded with it so
    /// that nothing comes between, after any [preface frames](Builder::preface_frames) the
    /// first request still carries, and as those are sent.
    ///
    /// # Panics
    ///
    /// This function panics if an undefined frame's payload is longer than a frame can
    /// carry (2^24 - 1 octets).
    pub fn send_before_next_request(&self, frames: impl IntoIterator<Item = PrefaceFrame>) {
        let frames: Vec<PrefaceFrame> = frames.into_iter().collect();
        assert!(fit(&frames));
        self.inner.send_before_next_request(frames);
    }

    /// Sends a WINDOW_UPDATE of `increment` for the connection (`stream_id` 0) or for the
    /// request recorded as `stream_id`, numbered as [`Self::send_priority`]'s streams are;
    /// not at all for a request this connection didn't send, or an increment its window
    /// can't take. It grows the window by `increment`, as the capacity released does.
    pub fn send_window_update(&self, stream_id: u32, increment: u32) {
        self.inner.send_window_update(stream_id, increment);
    }

    /// Tells that the request recorded as `recorded` won't be sent on this connection, so
    /// the frames following it (see [`Self::after_request`]) no longer wait for it.
    pub fn release_request(&self, recorded: u32) {
        self.inner.release_request(recorded);
    }

    /// Whether the request recorded as `recorded` went out on this connection.
    pub fn carries(&self, recorded: u32) -> bool {
        self.inner.carries(recorded)
    }

    /// The flow-controlled octets (padding included) of the DATA frames the connection
    /// sent so far, which the server's connection WINDOW_UPDATEs grant back.
    pub fn data_sent(&self) -> u64 {
        self.inner.data_sent()
    }

    /// Sends a GOAWAY frame of `reason` and `debug_data` naming `last_stream_id`, numbered
    /// as [`Self::send_priority`]'s streams are when it is a client-initiated one; the
    /// connection then closes without a GOAWAY of its own.
    pub fn send_go_away(&self, last_stream_id: u32, reason: Reason, debug_data: &[u8]) {
        self.inner.send_go_away(last_stream_id, reason, debug_data);
    }

    /// Leaves closing the connection to its caller, as a client relaying another's end does:
    /// it sends no GOAWAY of its own, only those [`Self::send_go_away`] sends, and stays open
    /// past the peer's GOAWAY until the peer closes it or its handles are dropped.
    pub fn leave_close_to_caller(&self) {
        self.inner.leave_close_to_caller();
    }

    /// Calls `go_away` with each GOAWAY the peer sends: its last stream, numbered as the
    /// connection requests were recorded on numbered it (see
    /// [`recorded_stream_id`](crate::ext::HeadersFrameOptions::recorded_stream_id)), as the
    /// latest request sent here on it or below it was, else as sent; its error code; and its
    /// debug data.
    pub fn on_go_away(&self, go_away: impl Fn(u32, Reason, Bytes) + Send + Sync + 'static) {
        self.inner.on_go_away(go_away);
    }

    /// Resolves once the frames sent through this connection's handles went out on its
    /// transport, or the connection ended.
    pub async fn sent(&self) {
        self.inner.sent().await;
    }

    /// Makes the receive window of the request recorded as `recorded`, if sent here, and
    /// the connection's for the data it receives, grow only by the WINDOW_UPDATEs
    /// [`Self::send_window_update`] sends, those of a peer that data is relayed to, rather
    /// than by the data released. Data released otherwise, or never, as a stream closes,
    /// still grows them.
    pub fn mirror_stream_window(&self, recorded: u32) {
        self.inner.mirror_stream_window(recorded);
    }

    /// The peer's connection preface, resolving once the connection received all of it
    /// (see [`ReceivedPreface`]).
    pub fn received_preface(&self) -> ReceivedPreface {
        self.preface.clone()
    }
}

/// Returns a `SendRequest` instance once it is ready to send at least one
/// request.
#[derive(Debug)]
pub struct ReadySendRequest<B: Buf> {
    inner: Option<SendRequest<B>>,
}

/// Manages all state associated with an HTTP/2 client connection.
///
/// A `Connection` is backed by an I/O resource (usually a TCP socket) and
/// implements the HTTP/2 client logic for that connection. It is responsible
/// for driving the internal state forward, performing the work requested of the
/// associated handles ([`SendRequest`], [`ResponseFuture`], [`SendStream`],
/// [`RecvStream`]).
///
/// `Connection` values are created by calling [`handshake`]. Once a
/// `Connection` value is obtained, the caller must repeatedly call [`poll`]
/// until `Ready` is returned. The easiest way to do this is to submit the
/// `Connection` instance to an [executor].
///
/// [module]: index.html
/// [`handshake`]: fn.handshake.html
/// [`SendRequest`]: struct.SendRequest.html
/// [`ResponseFuture`]: struct.ResponseFuture.html
/// [`SendStream`]: ../struct.SendStream.html
/// [`RecvStream`]: ../struct.RecvStream.html
/// [`poll`]: #method.poll
/// [executor]: https://docs.rs/futures/0.1/futures/future/trait.Executor.html
///
/// # Examples
///
/// ```
/// # use tokio::io::{AsyncRead, AsyncWrite};
/// # use http2::client;
/// # use http2::client::*;
/// #
/// # async fn doc<T>(my_io: T) -> Result<(), http2::Error>
/// # where T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
/// # {
///     let (send_request, connection) = client::handshake(my_io).await?;
///     // Submit the connection handle to an executor.
///     tokio::spawn(async { connection.await.expect("connection failed"); });
///
///     // Now, use `send_request` to initialize HTTP/2 streams.
///     // ...
/// # Ok(())
/// # }
/// #
/// # pub fn main() {}
/// ```
#[must_use = "futures do nothing unless polled"]
pub struct Connection<T, B: Buf = Bytes> {
    inner: proto::Connection<T, Peer, B>,
}

/// A future of an HTTP response.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ResponseFuture {
    inner: proto::OpaqueStreamRef,
    push_promise_consumed: bool,
}

/// A future of a pushed HTTP response.
///
/// We have to differentiate between pushed and non pushed because of the spec
/// <https://httpwg.org/specs/rfc7540.html#PUSH_PROMISE>
/// > PUSH_PROMISE frames MUST only be sent on a peer-initiated stream
/// > that is in either the "open" or "half-closed (remote)" state.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct PushedResponseFuture {
    inner: ResponseFuture,
}

/// A pushed response and corresponding request headers
#[derive(Debug)]
pub struct PushPromise {
    /// The request headers
    request: Request<()>,

    /// The pushed response
    response: PushedResponseFuture,
}

/// A stream of pushed responses and corresponding promised requests
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct PushPromises {
    inner: proto::OpaqueStreamRef,
}

/// Builds client connections with custom configuration values.
///
/// Methods can be chained in order to set the configuration values.
///
/// The client is constructed by calling [`handshake`] and passing the I/O
/// handle that will back the HTTP/2 server.
///
/// New instances of `Builder` are obtained via [`Builder::new`].
///
/// See function level documentation for details on the various client
/// configuration settings.
///
/// [`Builder::new`]: struct.Builder.html#method.new
/// [`handshake`]: struct.Builder.html#method.handshake
///
/// # Examples
///
/// ```
/// # use tokio::io::{AsyncRead, AsyncWrite};
/// # use http2::client::*;
/// # use bytes::Bytes;
/// #
/// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
///     -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
/// # {
/// // `client_fut` is a future representing the completion of the HTTP/2
/// // handshake.
/// let client_fut = Builder::new()
///     .initial_window_size(1_000_000)
///     .max_concurrent_streams(1000)
///     .handshake(my_io);
/// # client_fut.await
/// # }
/// #
/// # pub fn main() {}
/// ```
#[derive(Clone, Debug)]
pub struct Builder {
    /// Time to keep locally reset streams around before reaping.
    reset_stream_duration: Duration,

    /// Initial maximum number of locally initiated (send) streams.
    /// After receiving a SETTINGS frame from the remote peer,
    /// the connection will overwrite this value with the
    /// MAX_CONCURRENT_STREAMS specified in the frame.
    /// If no value is advertised by the remote peer in the initial SETTINGS
    /// frame, it will be set to usize::MAX.
    initial_max_send_streams: usize,

    /// Initial target window size for new connections.
    initial_target_connection_window_size: Option<u32>,

    /// Maximum amount of bytes to "buffer" for writing per stream.
    max_send_buffer_size: usize,

    /// Maximum number of locally reset streams to keep at a time.
    reset_stream_max: usize,

    /// Maximum number of remotely reset streams to allow in the pending
    /// accept queue.
    pending_accept_reset_stream_max: usize,

    /// Initial `Settings` frame to send as part of the handshake.
    settings: Settings,

    /// The stream ID of the first (lowest) stream. Subsequent streams will use
    /// monotonically increasing stream IDs.
    stream_id: StreamId,

    /// Maximum number of locally reset streams due to protocol error across
    /// the lifetime of the connection.
    ///
    /// When this gets exceeded, we issue GOAWAYs.
    local_max_error_reset_streams: Option<usize>,

    /// The headers frame pseudo order
    headers_pseudo_order: Option<PseudoOrder>,

    /// The headers frame stream dependency
    headers_stream_dependency: Option<StreamDependency>,

    /// Priority stream list
    priorities: Option<Priorities>,

    /// The exact SETTINGS parameters to send, in place of `settings`' own
    settings_frame: Option<Vec<(u16, u32)>>,

    /// Frames to send right ahead of the first request's HEADERS
    preface_frames: Vec<PrefaceFrame>,

    /// The unclaimed capacity the connection's and the streams' WINDOW_UPDATEs wait for
    connection_window_threshold: Option<u32>,
    stream_window_threshold: Option<u32>,

    /// How many of its frames each connection logs, when recording them
    frame_log_limit: Option<usize>,
}

#[derive(Debug)]
pub(crate) struct Peer;

// ===== impl SendRequest =====

impl<B> SendRequest<B>
where
    B: Buf,
{
    /// A handle sending frames of the caller's choosing on this connection while it
    /// lives: SETTINGS, PINGs, and the WINDOW_UPDATE policy.
    pub fn control(&self) -> Control {
        Control {
            inner: self.inner.control(),
            preface: self.preface.clone(),
        }
    }

    /// Returns `Ready` when the connection can initialize a new HTTP/2
    /// stream.
    ///
    /// This function must return `Ready` before `send_request` is called. When
    /// `Poll::Pending` is returned, the task will be notified once the readiness
    /// state changes.
    ///
    /// See [module] level docs for more details.
    ///
    /// [module]: index.html
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), crate::Error>> {
        ready!(self.inner.poll_pending_open(cx, self.pending.as_ref()))?;
        self.pending = None;
        Poll::Ready(Ok(()))
    }

    /// Consumes `self`, returning a future that returns `self` back once it is
    /// ready to send a request.
    ///
    /// This function should be called before calling `send_request`.
    ///
    /// This is a functional combinator for [`poll_ready`]. The returned future
    /// will call `SendStream::poll_ready` until `Ready`, then returns `self` to
    /// the caller.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use http2::client::*;
    /// # use http::*;
    /// # async fn doc(send_request: SendRequest<&'static [u8]>)
    /// # {
    /// // First, wait until the `send_request` handle is ready to send a new
    /// // request
    /// let mut send_request = send_request.ready().await.unwrap();
    /// // Use `send_request` here.
    /// # }
    /// # pub fn main() {}
    /// ```
    ///
    /// See [module] level docs for more details.
    ///
    /// [`poll_ready`]: #method.poll_ready
    /// [module]: index.html
    pub fn ready(self) -> ReadySendRequest<B> {
        ReadySendRequest { inner: Some(self) }
    }

    /// Sends a HTTP/2 request to the server.
    ///
    /// `send_request` initializes a new HTTP/2 stream on the associated
    /// connection, then sends the given request using this new stream. Only the
    /// request head is sent.
    ///
    /// On success, a [`ResponseFuture`] instance and [`SendStream`] instance
    /// are returned. The [`ResponseFuture`] instance is used to get the
    /// server's response and the [`SendStream`] instance is used to send a
    /// request body or trailers to the server over the same HTTP/2 stream.
    ///
    /// To send a request body or trailers, set `end_of_stream` to `false`.
    /// Then, use the returned [`SendStream`] instance to stream request body
    /// chunks or send trailers. If `end_of_stream` is **not** set to `false`
    /// then attempting to call [`SendStream::send_data`] or
    /// [`SendStream::send_trailers`] will result in an error.
    ///
    /// If no request body or trailers are to be sent, set `end_of_stream` to
    /// `true` and drop the returned [`SendStream`] instance.
    ///
    /// # A note on HTTP versions
    ///
    /// The provided `Request` will be encoded differently depending on the
    /// value of its version field. If the version is set to 2.0, then the
    /// request is encoded as per the specification recommends.
    ///
    /// If the version is set to a lower value, then the request is encoded to
    /// preserve the characteristics of HTTP 1.1 and lower. Specifically, host
    /// headers are permitted and the `:authority` pseudo header is not
    /// included.
    ///
    /// The caller should always set the request's version field to 2.0 unless
    /// specifically transmitting an HTTP 1.1 request over 2.0.
    ///
    /// # Examples
    ///
    /// Sending a request with no body
    ///
    /// ```rust
    /// # use http2::client::*;
    /// # use http::*;
    /// # async fn doc(send_request: SendRequest<&'static [u8]>)
    /// # {
    /// // First, wait until the `send_request` handle is ready to send a new
    /// // request
    /// let mut send_request = send_request.ready().await.unwrap();
    /// // Prepare the HTTP request to send to the server.
    /// let request = Request::get("https://www.example.com/")
    ///     .body(())
    ///     .unwrap();
    ///
    /// // Send the request to the server. Since we are not sending a
    /// // body or trailers, we can drop the `SendStream` instance.
    /// let (response, _) = send_request.send_request(request, true).unwrap();
    /// let response = response.await.unwrap();
    /// // Process the response
    /// # }
    /// # pub fn main() {}
    /// ```
    ///
    /// Sending a request with a body and trailers
    ///
    /// ```rust
    /// # use http2::client::*;
    /// # use http::*;
    /// # async fn doc(send_request: SendRequest<&'static [u8]>)
    /// # {
    /// // First, wait until the `send_request` handle is ready to send a new
    /// // request
    /// let mut send_request = send_request.ready().await.unwrap();
    ///
    /// // Prepare the HTTP request to send to the server.
    /// let request = Request::get("https://www.example.com/")
    ///     .body(())
    ///     .unwrap();
    ///
    /// // Send the request to the server. If we are not sending a
    /// // body or trailers, we can drop the `SendStream` instance.
    /// let (response, mut send_stream) = send_request
    ///     .send_request(request, false).unwrap();
    ///
    /// // At this point, one option would be to wait for send capacity.
    /// // Doing so would allow us to not hold data in memory that
    /// // cannot be sent. However, this is not a requirement, so this
    /// // example will skip that step. See `SendStream` documentation
    /// // for more details.
    /// send_stream.send_data(b"hello", false).unwrap();
    /// send_stream.send_data(b"world", false).unwrap();
    ///
    /// // Send the trailers.
    /// let mut trailers = HeaderMap::new();
    /// trailers.insert(
    ///     header::HeaderName::from_bytes(b"my-trailer").unwrap(),
    ///     header::HeaderValue::from_bytes(b"hello").unwrap());
    ///
    /// send_stream.send_trailers(trailers).unwrap();
    ///
    /// let response = response.await.unwrap();
    /// // Process the response
    /// # }
    /// # pub fn main() {}
    /// ```
    ///
    /// [`ResponseFuture`]: struct.ResponseFuture.html
    /// [`SendStream`]: ../struct.SendStream.html
    /// [`SendStream::send_data`]: ../struct.SendStream.html#method.send_data
    /// [`SendStream::send_trailers`]: ../struct.SendStream.html#method.send_trailers
    pub fn send_request(
        &mut self,
        request: Request<()>,
        end_of_stream: bool,
    ) -> Result<(ResponseFuture, SendStream<B>), crate::Error> {
        self.inner
            .send_request(request, end_of_stream, self.pending.as_ref())
            .map_err(Into::into)
            .map(|(stream, is_full)| {
                if stream.is_pending_open() && is_full {
                    // Only prevent sending another request when the request queue
                    // is not full.
                    self.pending = Some(stream.clone_to_opaque());
                }

                let response = ResponseFuture {
                    inner: stream.clone_to_opaque(),
                    push_promise_consumed: false,
                };

                let stream = SendStream::new(stream);

                (response, stream)
            })
    }

    /// Returns whether the [extended CONNECT protocol][1] is enabled or not.
    ///
    /// This setting is configured by the server peer by sending the
    /// [`SETTINGS_ENABLE_CONNECT_PROTOCOL` parameter][2] in a `SETTINGS` frame.
    /// This method returns the currently acknowledged value received from the
    /// remote.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
    /// [2]: https://datatracker.ietf.org/doc/html/rfc8441#section-3
    pub fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.inner.is_extended_connect_protocol_enabled()
    }

    /// Returns the current max send streams
    pub fn current_max_send_streams(&self) -> usize {
        self.inner.current_max_send_streams()
    }

    /// Returns the current max recv streams
    pub fn current_max_recv_streams(&self) -> usize {
        self.inner.current_max_recv_streams()
    }
}

impl<B> fmt::Debug for SendRequest<B>
where
    B: Buf,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SendRequest").finish()
    }
}

impl<B> Clone for SendRequest<B>
where
    B: Buf,
{
    fn clone(&self) -> Self {
        SendRequest {
            inner: self.inner.clone(),
            pending: None,
            preface: self.preface.clone(),
        }
    }
}

#[cfg(feature = "unstable")]
impl<B> SendRequest<B>
where
    B: Buf,
{
    /// Returns the number of active streams.
    ///
    /// An active stream is a stream that has not yet transitioned to a closed
    /// state.
    pub fn num_active_streams(&self) -> usize {
        self.inner.num_active_streams()
    }

    /// Returns the number of streams that are held in memory.
    ///
    /// A wired stream is a stream that is either active or is closed but must
    /// stay in memory for some reason. For example, there are still outstanding
    /// userspace handles pointing to the slot.
    pub fn num_wired_streams(&self) -> usize {
        self.inner.num_wired_streams()
    }
}

// ===== impl ReadySendRequest =====

impl<B> Future for ReadySendRequest<B>
where
    B: Buf,
{
    type Output = Result<SendRequest<B>, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.inner {
            Some(send_request) => {
                ready!(send_request.poll_ready(cx))?;
            }
            None => panic!("called `poll` after future completed"),
        }

        Poll::Ready(Ok(self.inner.take().unwrap()))
    }
}

// ===== impl Builder =====

impl Builder {
    /// Returns a new client builder instance initialized with default
    /// configuration values.
    ///
    /// Configuration methods can be chained on the return value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .initial_window_size(1_000_000)
    ///     .max_concurrent_streams(1000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn new() -> Builder {
        Builder {
            max_send_buffer_size: proto::DEFAULT_MAX_SEND_BUFFER_SIZE,
            reset_stream_duration: Duration::from_secs(proto::DEFAULT_RESET_STREAM_SECS),
            reset_stream_max: proto::DEFAULT_RESET_STREAM_MAX,
            pending_accept_reset_stream_max: proto::DEFAULT_REMOTE_RESET_STREAM_MAX,
            initial_target_connection_window_size: None,
            initial_max_send_streams: usize::MAX,
            settings: Default::default(),
            stream_id: 1.into(),
            local_max_error_reset_streams: Some(proto::DEFAULT_LOCAL_RESET_COUNT_MAX),
            headers_pseudo_order: None,
            headers_stream_dependency: None,
            priorities: None,
            settings_frame: None,
            preface_frames: Vec::new(),
            connection_window_threshold: None,
            stream_window_threshold: None,
            frame_log_limit: None,
        }
    }

    /// Indicates the initial window size (in octets) for stream-level
    /// flow control for received data.
    ///
    /// The initial window of a stream is used as part of flow control. For more
    /// details, see [`FlowControl`].
    ///
    /// The default value is 65,535.
    ///
    /// [`FlowControl`]: ../struct.FlowControl.html
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .initial_window_size(1_000_000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn initial_window_size(&mut self, size: u32) -> &mut Self {
        self.settings.set_initial_window_size(Some(size));
        self
    }

    /// Indicates the initial window size (in octets) for connection-level flow control
    /// for received data.
    ///
    /// The initial window of a connection is used as part of flow control. For more details,
    /// see [`FlowControl`].
    ///
    /// The default value is 65,535.
    ///
    /// [`FlowControl`]: ../struct.FlowControl.html
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .initial_connection_window_size(1_000_000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn initial_connection_window_size(&mut self, size: u32) -> &mut Self {
        self.initial_target_connection_window_size = Some(size);
        self
    }

    /// Indicates the size (in octets) of the largest HTTP/2 frame payload that the
    /// configured client is able to accept.
    ///
    /// The sender may send data frames that are **smaller** than this value,
    /// but any data larger than `max` will be broken up into multiple `DATA`
    /// frames.
    ///
    /// The value **must** be between 16,384 and 16,777,215. The default value is 16,384.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .max_frame_size(1_000_000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    ///
    /// # Panics
    ///
    /// This function panics if `max` is not within the legal range specified
    /// above.
    pub fn max_frame_size(&mut self, max: u32) -> &mut Self {
        self.settings.set_max_frame_size(Some(max));
        self
    }

    /// Sets the max size of received header frames.
    ///
    /// This advisory setting informs a peer of the maximum size of header list
    /// that the sender is prepared to accept, in octets. The value is based on
    /// the uncompressed size of header fields, including the length of the name
    /// and value in octets plus an overhead of 32 octets for each header field.
    ///
    /// This setting is also used to limit the maximum amount of data that is
    /// buffered to decode HEADERS frames.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .max_header_list_size(16 * 1024)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn max_header_list_size(&mut self, max: u32) -> &mut Self {
        self.settings.set_max_header_list_size(Some(max));
        self
    }

    /// Sets the maximum number of concurrent streams.
    ///
    /// The maximum concurrent streams setting only controls the maximum number
    /// of streams that can be initiated by the remote peer. In other words,
    /// when this setting is set to 100, this does not limit the number of
    /// concurrent streams that can be created by the caller.
    ///
    /// It is recommended that this value be no smaller than 100, so as to not
    /// unnecessarily limit parallelism. However, any value is legal, including
    /// 0. If `max` is set to 0, then the remote will not be permitted to
    /// initiate streams.
    ///
    /// Note that streams in the reserved state, i.e., push promises that have
    /// been reserved but the stream has not started, do not count against this
    /// setting.
    ///
    /// Also note that if the remote *does* exceed the value set here, it is not
    /// a protocol level error. Instead, the `http2` library will immediately reset
    /// the stream.
    ///
    /// See [Section 5.1.2] in the HTTP/2 spec for more details.
    ///
    /// [Section 5.1.2]: https://http2.github.io/http2-spec/#rfc.section.5.1.2
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .max_concurrent_streams(1000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn max_concurrent_streams(&mut self, max: u32) -> &mut Self {
        self.settings.set_max_concurrent_streams(Some(max));
        self
    }

    /// Sets the initial maximum of locally initiated (send) streams.
    ///
    /// The initial settings will be overwritten by the remote peer when
    /// the SETTINGS frame is received. The new value will be set to the
    /// `max_concurrent_streams()` from the frame. If no value is advertised in
    /// the initial SETTINGS frame from the remote peer as part of
    /// [HTTP/2 Connection Preface], `usize::MAX` will be set.
    ///
    /// This setting prevents the caller from exceeding this number of
    /// streams that are counted towards the concurrency limit.
    ///
    /// Sending streams past the limit returned by the peer will be treated
    /// as a stream error of type PROTOCOL_ERROR or REFUSED_STREAM.
    ///
    /// See [Section 5.1.2] in the HTTP/2 spec for more details.
    ///
    /// The default value is `usize::MAX`.
    ///
    /// [HTTP/2 Connection Preface]: https://httpwg.org/specs/rfc9113.html#preface
    /// [Section 5.1.2]: https://httpwg.org/specs/rfc9113.html#rfc.section.5.1.2
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .initial_max_send_streams(1000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn initial_max_send_streams(&mut self, initial: usize) -> &mut Self {
        self.initial_max_send_streams = initial;
        self
    }

    /// Sets the maximum number of concurrent locally reset streams.
    ///
    /// When a stream is explicitly reset, the HTTP/2 specification requires
    /// that any further frames received for that stream must be ignored for
    /// "some time".
    ///
    /// In order to satisfy the specification, internal state must be maintained
    /// to implement the behavior. This state grows linearly with the number of
    /// streams that are locally reset.
    ///
    /// The `max_concurrent_reset_streams` setting configures sets an upper
    /// bound on the amount of state that is maintained. When this max value is
    /// reached, the oldest reset stream is purged from memory.
    ///
    /// Once the stream has been fully purged from memory, any additional frames
    /// received for that stream will result in a connection level protocol
    /// error, forcing the connection to terminate.
    ///
    /// The default value is currently 50.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .max_concurrent_reset_streams(1000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn max_concurrent_reset_streams(&mut self, max: usize) -> &mut Self {
        self.reset_stream_max = max;
        self
    }

    /// Sets the duration to remember locally reset streams.
    ///
    /// When a stream is explicitly reset, the HTTP/2 specification requires
    /// that any further frames received for that stream must be ignored for
    /// "some time".
    ///
    /// In order to satisfy the specification, internal state must be maintained
    /// to implement the behavior. This state grows linearly with the number of
    /// streams that are locally reset.
    ///
    /// The `reset_stream_duration` setting configures the max amount of time
    /// this state will be maintained in memory. Once the duration elapses, the
    /// stream state is purged from memory.
    ///
    /// Once the stream has been fully purged from memory, any additional frames
    /// received for that stream will result in a connection level protocol
    /// error, forcing the connection to terminate.
    ///
    /// The default value is currently 1 second.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use std::time::Duration;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .reset_stream_duration(Duration::from_secs(10))
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn reset_stream_duration(&mut self, dur: Duration) -> &mut Self {
        self.reset_stream_duration = dur;
        self
    }

    /// Sets the maximum number of local resets due to protocol errors made by the remote end.
    ///
    /// Invalid frames and many other protocol errors will lead to resets being generated for those streams.
    /// Too many of these often indicate a malicious client, and there are attacks which can abuse this to DOS servers.
    /// This limit protects against these DOS attacks by limiting the amount of resets we can be forced to generate.
    ///
    /// When the number of local resets exceeds this threshold, the client will close the connection.
    ///
    /// If you really want to disable this, supply [`Option::None`] here.
    /// Disabling this is not recommended and may expose you to DOS attacks.
    ///
    /// The default value is currently 1024, but could change.
    pub fn max_local_error_reset_streams(&mut self, max: Option<usize>) -> &mut Self {
        self.local_max_error_reset_streams = max;
        self
    }

    /// Sets the maximum number of pending-accept remotely-reset streams.
    ///
    /// Streams that have been received by the peer, but not accepted by the
    /// user, can also receive a RST_STREAM. This is a legitimate pattern: one
    /// could send a request and then shortly after, realize it is not needed,
    /// sending a CANCEL.
    ///
    /// However, since those streams are now "closed", they don't count towards
    /// the max concurrent streams. So, they will sit in the accept queue,
    /// using memory.
    ///
    /// When the number of remotely-reset streams sitting in the pending-accept
    /// queue reaches this maximum value, a connection error with the code of
    /// `ENHANCE_YOUR_CALM` will be sent to the peer, and returned by the
    /// `Future`.
    ///
    /// The default value is currently 20, but could change.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .max_pending_accept_reset_streams(100)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn max_pending_accept_reset_streams(&mut self, max: usize) -> &mut Self {
        self.pending_accept_reset_stream_max = max;
        self
    }

    /// Sets the maximum send buffer size per stream.
    ///
    /// Once a stream has buffered up to (or over) the maximum, the stream's
    /// flow control will not "poll" additional capacity. Once bytes for the
    /// stream have been written to the connection, the send buffer capacity
    /// will be freed up again.
    ///
    /// The default is currently ~400KB, but may change.
    ///
    /// # Panics
    ///
    /// This function panics if `max` is larger than `u32::MAX`.
    pub fn max_send_buffer_size(&mut self, max: usize) -> &mut Self {
        assert!(max <= u32::MAX as usize);
        self.max_send_buffer_size = max;
        self
    }

    /// Enables or disables server push promises.
    ///
    /// This value is included in the initial SETTINGS handshake.
    /// Setting this value to value to
    /// false in the initial SETTINGS handshake guarantees that the remote server
    /// will never send a push promise.
    ///
    /// This setting can be changed during the life of a single HTTP/2
    /// connection by sending another settings frame updating the value.
    ///
    /// Default value: `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use std::time::Duration;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .enable_push(false)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn enable_push(&mut self, enabled: bool) -> &mut Self {
        self.settings.set_enable_push(enabled);
        self
    }

    /// Sets the header table size.
    ///
    /// This setting informs the peer of the maximum size of the header compression
    /// table used to encode header blocks, in octets. The encoder may select any value
    /// equal to or less than the header table size specified by the sender.
    ///
    /// The default value is 4,096.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .header_table_size(1_000_000)
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn header_table_size(&mut self, size: u32) -> &mut Self {
        self.settings.set_header_table_size(Some(size));
        self
    }

    /// Sets the enable connect protocol.
    pub fn enable_connect_protocol(&mut self, enabled: bool) -> &mut Self {
        self.settings
            .set_enable_connect_protocol(Some(enabled as _));
        self
    }

    /// Disable RFC 7540 Stream Priorities (set to `true` to disable).
    /// [RFC 9218]: <https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1>
    pub fn no_rfc7540_priorities(&mut self, enabled: bool) -> &mut Self {
        self.settings.set_no_rfc7540_priorities(enabled);
        self
    }

    /// Configures custom experimental HTTP/2 setting.
    ///
    /// This setting is reserved for future use or experimental purposes.
    /// Enabling or disabling it may have no effect unless explicitly supported
    /// by the server or client implementation.
    //
    // - Experimental feature – subject to removal without notice
    #[cfg(feature = "unstable")]
    pub fn experimental_settings(
        &mut self,
        experimental_settings: ExperimentalSettings,
    ) -> &mut Self {
        self.settings
            .set_experimental_settings(experimental_settings);
        self
    }

    /// Sets the first stream ID to something other than 1.
    #[cfg(feature = "unstable")]
    pub fn initial_stream_id(&mut self, stream_id: u32) -> &mut Self {
        self.stream_id = stream_id.into();
        assert!(
            self.stream_id.is_client_initiated(),
            "stream id must be odd"
        );
        self
    }

    /// Sets the order of settings parameters in the initial SETTINGS frame.
    ///
    /// This determines the order in which settings are sent during the HTTP/2 handshake.
    /// Customizing the order may be useful for testing or protocol compliance.
    pub fn settings_order(&mut self, order: SettingsOrder) -> &mut Self {
        self.settings.set_settings_order(order);
        self
    }

    /// Sets the HTTP/2 pseudo-header field order for outgoing HEADERS frames.
    ///
    /// This determines the order in which pseudo-header fields (such as `:method`, `:scheme`, etc.)
    /// are encoded in the HEADERS frame. Customizing the order may be useful for interoperability
    /// or testing purposes.
    pub fn headers_pseudo_order(&mut self, order: PseudoOrder) -> &mut Self {
        self.headers_pseudo_order = Some(order.into());
        self
    }

    /// Sets the stream dependency and weight for the outgoing HEADERS frame.
    ///
    /// This configures the priority of the stream by specifying its dependency and weight,
    /// as defined by the HTTP/2 priority mechanism. This can be used to influence how the
    /// server allocates resources to this stream relative to others.
    pub fn headers_stream_dependency(&mut self, stream_dependency: StreamDependency) -> &mut Self {
        self.headers_stream_dependency = Some(stream_dependency);
        self
    }

    /// Sets the list of PRIORITY frames to be sent immediately after the connection is established,
    /// but before the first request is sent.
    ///
    /// This allows you to pre-configure the HTTP/2 stream dependency tree by specifying a set of
    /// PRIORITY frames that will be sent as part of the connection preface. This can be useful for
    /// optimizing resource allocation or testing custom stream prioritization strategies.
    ///
    /// Each `Priority` in the list must have a valid (non-zero) stream ID. Any priority with a
    /// stream ID of zero will be ignored.
    pub fn priorities(&mut self, priorities: Priorities) -> &mut Self {
        self.priorities = Some(priorities);
        self
    }

    /// Sends exactly `params` as the connection preface's SETTINGS frame: each
    /// `(identifier, value)` in order, unknown identifiers and repeats included.
    ///
    /// The connection then behaves as the frame says: the known parameters it carries
    /// replace those set by [`header_table_size`], [`enable_push`],
    /// [`max_concurrent_streams`], [`initial_window_size`], [`max_frame_size`],
    /// [`max_header_list_size`], [`enable_connect_protocol`] and
    /// [`no_rfc7540_priorities`], the ones it leaves out keep their protocol defaults,
    /// and [`settings_order`] no longer applies.
    ///
    /// [`header_table_size`]: Self::header_table_size
    /// [`enable_push`]: Self::enable_push
    /// [`max_concurrent_streams`]: Self::max_concurrent_streams
    /// [`initial_window_size`]: Self::initial_window_size
    /// [`max_frame_size`]: Self::max_frame_size
    /// [`max_header_list_size`]: Self::max_header_list_size
    /// [`enable_connect_protocol`]: Self::enable_connect_protocol
    /// [`no_rfc7540_priorities`]: Self::no_rfc7540_priorities
    /// [`settings_order`]: Self::settings_order
    pub fn settings_frame(&mut self, params: impl IntoIterator<Item = (u16, u32)>) -> &mut Self {
        self.settings_frame = Some(params.into_iter().collect());
        self
    }

    /// Sends `frames` once, in order, after the SETTINGS frame and right before the first
    /// request's HEADERS frame, encoded with it so that nothing comes between: connection
    /// WINDOW_UPDATEs (the connection's receive window grows by each increment, so the
    /// [target window](Self::initial_connection_window_size) should leave it be), PRIORITY
    /// frames, numbered as the first request's
    /// [`recorded_stream_id`](crate::ext::HeadersFrameOptions::recorded_stream_id) says, and
    /// frames of types HTTP/2 doesn't define, sent as given.
    ///
    /// # Panics
    ///
    /// This function panics if an undefined frame's payload is longer than a frame can
    /// carry (2^24 - 1 octets).
    pub fn preface_frames(&mut self, frames: impl IntoIterator<Item = PrefaceFrame>) -> &mut Self {
        self.preface_frames = frames.into_iter().collect();
        assert!(fit(&self.preface_frames));
        self
    }

    /// Sends a WINDOW_UPDATE once `connection`, for the connection, or `stream`, for a
    /// stream, bytes of received data were released since the last one, rather than once
    /// half the window was; `None` keeps half the window.
    pub fn window_update_thresholds(
        &mut self,
        connection: Option<u32>,
        stream: Option<u32>,
    ) -> &mut Self {
        self.connection_window_threshold = connection;
        self.stream_window_threshold = stream;
        self
    }

    /// Records the frames each connection sends that shape its HTTP/2 fingerprint.
    ///
    /// Each connection logs the frames it sends but DATA, in wire order, up to `limit` of
    /// them, in a [`FrameLog`], and those it receives but DATA in another, and each
    /// response carries a [`HeadersFrame`](crate::ext::HeadersFrame) extension with its
    /// request's HEADERS frame's stream, priority fields and pseudo-header order, and
    /// both logs.
    ///
    /// Not recorded by default.
    pub fn record_frames(&mut self, limit: usize) -> &mut Self {
        self.frame_log_limit = Some(limit);
        self
    }

    /// Creates a new configured HTTP/2 client backed by `io`.
    ///
    /// It is expected that `io` already be in an appropriate state to commence
    /// the [HTTP/2 handshake]. The handshake is completed once both the connection
    /// preface and the initial settings frame is sent by the client.
    ///
    /// The handshake future does not wait for the initial settings frame from the
    /// server.
    ///
    /// Returns a future which resolves to the [`Connection`] / [`SendRequest`]
    /// tuple once the HTTP/2 handshake has been completed.
    ///
    /// This function also allows the caller to configure the send payload data
    /// type. See [Outbound data type] for more details.
    ///
    /// [HTTP/2 handshake]: http://httpwg.org/specs/rfc7540.html#ConnectionHeader
    /// [`Connection`]: struct.Connection.html
    /// [`SendRequest`]: struct.SendRequest.html
    /// [Outbound data type]: ../index.html#outbound-data-type.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// # use bytes::Bytes;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    ///     -> Result<((SendRequest<Bytes>, Connection<T, Bytes>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .handshake(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    ///
    /// Configures the send-payload data type. In this case, the outbound data
    /// type will be `&'static [u8]`.
    ///
    /// ```
    /// # use tokio::io::{AsyncRead, AsyncWrite};
    /// # use http2::client::*;
    /// #
    /// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T)
    /// # -> Result<((SendRequest<&'static [u8]>, Connection<T, &'static [u8]>)), http2::Error>
    /// # {
    /// // `client_fut` is a future representing the completion of the HTTP/2
    /// // handshake.
    /// let client_fut = Builder::new()
    ///     .handshake::<_, &'static [u8]>(my_io);
    /// # client_fut.await
    /// # }
    /// #
    /// # pub fn main() {}
    /// ```
    pub fn handshake<T, B>(
        &self,
        io: T,
    ) -> impl Future<Output = Result<(SendRequest<B>, Connection<T, B>), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        B: Buf,
    {
        Connection::handshake2(io, self.clone())
    }
}

impl Default for Builder {
    fn default() -> Builder {
        Builder::new()
    }
}

/// Whether each of `frames` fits in a frame (see [`Builder::preface_frames`]).
fn fit(frames: &[PrefaceFrame]) -> bool {
    frames.iter().all(|frame| match frame {
        PrefaceFrame::Unknown(frame) => frame.payload.len() <= MAX_MAX_FRAME_SIZE as usize,
        _ => true,
    })
}

/// Creates a new configured HTTP/2 client with default configuration
/// values backed by `io`.
///
/// It is expected that `io` already be in an appropriate state to commence
/// the [HTTP/2 handshake]. See [Handshake] for more details.
///
/// Returns a future which resolves to the [`Connection`] / [`SendRequest`]
/// tuple once the HTTP/2 handshake has been completed. The returned
/// [`Connection`] instance will be using default configuration values. Use
/// [`Builder`] to customize the configuration values used by a [`Connection`]
/// instance.
///
/// [HTTP/2 handshake]: http://httpwg.org/specs/rfc7540.html#ConnectionHeader
/// [Handshake]: ../index.html#handshake
/// [`Connection`]: struct.Connection.html
/// [`SendRequest`]: struct.SendRequest.html
///
/// # Examples
///
/// ```
/// # use tokio::io::{AsyncRead, AsyncWrite};
/// # use http2::client;
/// # use http2::client::*;
/// #
/// # async fn doc<T: AsyncRead + AsyncWrite + Unpin>(my_io: T) -> Result<(), http2::Error>
/// # {
/// let (send_request, connection) = client::handshake(my_io).await?;
/// // The HTTP/2 handshake has completed, now start polling
/// // `connection` and use `send_request` to send requests to the
/// // server.
/// # Ok(())
/// # }
/// #
/// # pub fn main() {}
/// ```
pub async fn handshake<T>(io: T) -> Result<(SendRequest<Bytes>, Connection<T, Bytes>), crate::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let builder = Builder::new();

    #[cfg(feature = "tracing")]
    return builder
        .handshake(io)
        .instrument(::tracing::trace_span!("client_handshake"))
        .await;

    #[cfg(not(feature = "tracing"))]
    return builder.handshake(io).await;
}

// ===== impl Connection =====

impl<T, B> Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    async fn handshake2(
        io: T,
        mut builder: Builder,
    ) -> Result<(SendRequest<B>, Connection<T, B>), crate::Error> {
        if let Some(params) = builder.settings_frame.take() {
            builder.settings.set_wire(params);
        }

        // Create the codec
        let mut codec = Codec::new(io);

        if let Some(max) = builder.settings.max_frame_size() {
            codec.set_max_recv_frame_size(max as usize);
        }

        if let Some(max) = builder.settings.max_header_list_size() {
            codec.set_max_recv_header_list_size(max as usize);
        }

        let frame_log = builder.frame_log_limit.map(FrameLog::new);
        if let Some(log) = &frame_log {
            codec.set_frame_log(log.clone());
        }
        let received_frame_log = builder.frame_log_limit.map(FrameLog::new);
        if let Some(log) = &received_frame_log {
            codec.set_received_frame_log(log.clone());
        }
        let preface = ReceivedPreface::default();
        codec.set_received_preface(&preface);

        // The preface's opening bytes go out with the initial settings frame, in one write
        // as clients send them.
        codec.buffer_raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // Send initial settings frame, the connection's own: a relaying caller's peer
        // acknowledged its own preface's
        let mut settings = builder.settings.clone();
        settings.set_own();
        codec
            .buffer(settings.into())
            .expect("invalid SETTINGS frame");

        let inner = proto::Connection::new(
            codec,
            proto::Config {
                next_stream_id: builder.stream_id,
                initial_max_send_streams: builder.initial_max_send_streams,
                max_send_buffer_size: builder.max_send_buffer_size,
                reset_stream_duration: builder.reset_stream_duration,
                reset_stream_max: builder.reset_stream_max,
                remote_reset_stream_max: builder.pending_accept_reset_stream_max,
                local_error_reset_streams_max: builder.local_max_error_reset_streams,
                headers_pseudo_order: builder.headers_pseudo_order,
                headers_stream_dependency: builder.headers_stream_dependency,
                priorities: builder.priorities,
                preface_frames: builder.preface_frames,
                connection_window_threshold: builder.connection_window_threshold,
                stream_window_threshold: builder.stream_window_threshold,
                frame_log,
                received_frame_log,
                settings: builder.settings,
            },
        );
        let send_request = SendRequest {
            inner: inner.streams().clone(),
            pending: None,
            preface,
        };

        let mut connection = Connection { inner };
        if let Some(sz) = builder.initial_target_connection_window_size {
            connection.set_target_window_size(sz);
        }

        Ok((send_request, connection))
    }

    /// Sets the target window size for the whole connection.
    ///
    /// If `size` is greater than the current value, then a `WINDOW_UPDATE`
    /// frame will be immediately sent to the remote, increasing the connection
    /// level window by `size - current_value`.
    ///
    /// If `size` is less than the current value, nothing will happen
    /// immediately. However, as window capacity is released by
    /// [`FlowControl`] instances, no `WINDOW_UPDATE` frames will be sent
    /// out until the number of "in flight" bytes drops below `size`.
    ///
    /// The default value is 65,535.
    ///
    /// See [`FlowControl`] documentation for more details.
    ///
    /// [`FlowControl`]: ../struct.FlowControl.html
    /// [library level]: ../index.html#flow-control
    pub fn set_target_window_size(&mut self, size: u32) {
        assert!(size <= proto::MAX_WINDOW_SIZE);
        self.inner.set_target_window_size(size);
    }

    /// Set a new `INITIAL_WINDOW_SIZE` setting (in octets) for stream-level
    /// flow control for received data.
    ///
    /// The `SETTINGS` will be sent to the remote, and only applied once the
    /// remote acknowledges the change.
    ///
    /// This can be used to increase or decrease the window size for existing
    /// streams.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call is still pending acknowledgement
    /// from the remote endpoint.
    pub fn set_initial_window_size(&mut self, size: u32) -> Result<(), crate::Error> {
        assert!(size <= proto::MAX_WINDOW_SIZE);
        self.inner.set_initial_window_size(size)?;
        Ok(())
    }

    /// Takes a `PingPong` instance from the connection.
    ///
    /// # Note
    ///
    /// This may only be called once. Calling multiple times will return `None`.
    pub fn ping_pong(&mut self) -> Option<PingPong> {
        self.inner.take_user_pings().map(PingPong::new)
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by this client.
    ///
    /// This limit is configured by the server peer by sending the
    /// [`SETTINGS_MAX_CONCURRENT_STREAMS` parameter][1] in a `SETTINGS` frame.
    /// This method returns the currently acknowledged value received from the
    /// remote.
    ///
    /// [1]: https://tools.ietf.org/html/rfc7540#section-5.1.2
    pub fn max_concurrent_send_streams(&self) -> usize {
        self.inner.max_send_streams()
    }
    /// Returns the maximum number of concurrent streams that may be initiated
    /// by the server on this connection.
    ///
    /// This returns the value of the [`SETTINGS_MAX_CONCURRENT_STREAMS`
    /// parameter][1] sent in a `SETTINGS` frame that has been
    /// acknowledged by the remote peer. The value to be sent is configured by
    /// the [`Builder::max_concurrent_streams`][2] method before handshaking
    /// with the remote peer.
    ///
    /// [1]: https://tools.ietf.org/html/rfc7540#section-5.1.2
    /// [2]: ../struct.Builder.html#method.max_concurrent_streams
    pub fn max_concurrent_recv_streams(&self) -> usize {
        self.inner.max_recv_streams()
    }
}

impl<T, B> Future for Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    type Output = Result<(), crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.maybe_close_connection_if_no_streams();
        let had_streams_or_refs = self.inner.has_streams_or_other_references();
        let result = self.inner.poll(cx).map_err(Into::into);
        // if we had streams/refs, and don't anymore, wake up one more time to
        // ensure proper shutdown
        if result.is_pending()
            && had_streams_or_refs
            && !self.inner.has_streams_or_other_references()
        {
            tracing::trace!("last stream closed during poll, wake again");
            cx.waker().wake_by_ref();
        }
        result
    }
}

impl<T, B> fmt::Debug for Connection<T, B>
where
    T: AsyncRead + AsyncWrite,
    T: fmt::Debug,
    B: fmt::Debug + Buf,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, fmt)
    }
}

// ===== impl ResponseFuture =====

impl Future for ResponseFuture {
    type Output = Result<Response<RecvStream>, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (parts, _) = ready!(self.inner.poll_response(cx))?.into_parts();
        let body = RecvStream::new(FlowControl::new(self.inner.clone()));

        Poll::Ready(Ok(Response::from_parts(parts, body)))
    }
}

impl ResponseFuture {
    /// Returns the stream ID of the response stream.
    ///
    /// # Panics
    ///
    /// If the lock on the stream store has been poisoned.
    pub fn stream_id(&self) -> crate::StreamId {
        crate::StreamId::from_internal(self.inner.stream_id())
    }

    /// Polls for informational responses (1xx status codes).
    ///
    /// This method should be called before polling the main response future
    /// to check for any informational responses that have been received.
    ///
    /// Returns `Poll::Ready(Some(response))` if an informational response is available,
    /// `Poll::Ready(None)` if no more informational responses are expected,
    /// or `Poll::Pending` if no informational response is currently available.
    pub fn poll_informational(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Response<()>, crate::Error>>> {
        self.inner.poll_informational(cx).map_err(Into::into)
    }

    /// Returns a stream of PushPromises
    ///
    /// # Panics
    ///
    /// If this method has been called before
    /// or the stream was itself was pushed
    pub fn push_promises(&mut self) -> PushPromises {
        if self.push_promise_consumed {
            panic!("Reference to push promises stream taken!");
        }
        self.push_promise_consumed = true;
        PushPromises {
            inner: self.inner.clone(),
        }
    }
}

// ===== impl PushPromises =====

impl PushPromises {
    /// Get the next `PushPromise`.
    pub async fn push_promise(&mut self) -> Option<Result<PushPromise, crate::Error>> {
        crate::poll_fn(move |cx| self.poll_push_promise(cx)).await
    }

    #[doc(hidden)]
    pub fn poll_push_promise(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<PushPromise, crate::Error>>> {
        match self.inner.poll_pushed(cx) {
            Poll::Ready(Some(Ok((request, response)))) => {
                let response = PushedResponseFuture {
                    inner: ResponseFuture {
                        inner: response,
                        push_promise_consumed: false,
                    },
                };
                Poll::Ready(Some(Ok(PushPromise { request, response })))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "stream")]
impl futures_core::Stream for PushPromises {
    type Item = Result<PushPromise, crate::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_push_promise(cx)
    }
}

// ===== impl PushPromise =====

impl PushPromise {
    /// Returns a reference to the push promise's request headers.
    pub fn request(&self) -> &Request<()> {
        &self.request
    }

    /// Returns a mutable reference to the push promise's request headers.
    pub fn request_mut(&mut self) -> &mut Request<()> {
        &mut self.request
    }

    /// Consumes `self`, returning the push promise's request headers and
    /// response future.
    pub fn into_parts(self) -> (Request<()>, PushedResponseFuture) {
        (self.request, self.response)
    }
}

// ===== impl PushedResponseFuture =====

impl Future for PushedResponseFuture {
    type Output = Result<Response<RecvStream>, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

impl PushedResponseFuture {
    /// Returns the stream ID of the response stream.
    ///
    /// # Panics
    ///
    /// If the lock on the stream store has been poisoned.
    pub fn stream_id(&self) -> crate::StreamId {
        self.inner.stream_id()
    }
}

// ===== impl Peer =====

impl Peer {
    pub fn convert_send_message(
        id: StreamId,
        request: Request<()>,
        protocol: Option<Protocol>,
        order: Option<HeaderOrder>,
        end_of_stream: bool,
        pseudo_order: Option<PseudoOrder>,
        headers_stream_dependency: Option<StreamDependency>,
    ) -> Result<Headers, SendError> {
        use http::request::Parts;

        let (
            Parts {
                method,
                uri,
                headers,
                version,
                ..
            },
            _,
        ) = request.into_parts();

        let is_connect = method == Method::CONNECT;

        // Build the set pseudo header set. All requests will include `method`
        // and `path`.
        let mut pseudo = Pseudo::request(method, uri, protocol);

        // If the pseudo order is set, then set the pseudo order
        if let Some(pseudo_order) = pseudo_order {
            pseudo.set_pseudo_order(pseudo_order);
        }

        if pseudo.scheme.is_none() {
            // If the scheme is not set, then there are a two options.
            //
            // 1) Authority is not set. In this case, a request was issued with
            //    a relative URI. This is permitted **only** when forwarding
            //    HTTP 1.x requests. If the HTTP version is set to 2.0, then
            //    this is an error.
            //
            // 2) Authority is set, then the HTTP method *must* be CONNECT.
            //
            // It is not possible to have a scheme but not an authority set (the
            // `http` crate does not allow it).
            //
            if pseudo.authority.is_none() {
                if version == Version::HTTP_2 {
                    return Err(UserError::MissingUriSchemeAndAuthority.into());
                } else {
                    // This is acceptable as per the above comment. However,
                    // HTTP/2 requires that a scheme is set. Since we are
                    // forwarding an HTTP 1.1 request, the scheme is set to
                    // "http".
                    pseudo.set_scheme(uri::Scheme::HTTP);
                }
            } else if !is_connect {
                // TODO: Error
            }
        }

        // Create the HEADERS frame
        let mut headers_frame = Headers::new(id, pseudo, headers);
        if let Some(order) = order {
            headers_frame.set_header_order(order);
        }
        if let Some(stream_dep) = headers_stream_dependency {
            headers_frame.set_stream_dependency(stream_dep);
        }

        if end_of_stream {
            headers_frame.set_end_stream()
        }

        Ok(headers_frame)
    }
}

impl proto::Peer for Peer {
    type Poll = Response<()>;

    #[cfg(feature = "tracing")]
    const NAME: &'static str = "Client";

    fn r#dyn() -> proto::DynPeer {
        proto::DynPeer::Client
    }

    /*
    fn is_server() -> bool {
        false
    }
    */

    fn convert_poll_message(
        pseudo: Pseudo,
        fields: HeaderMap,
        stream_id: StreamId,
    ) -> Result<Self::Poll, Error> {
        let mut b = Response::builder();

        b = b.version(Version::HTTP_2);

        if let Some(status) = pseudo.status {
            b = b.status(status);
        }

        let mut response = match b.body(()) {
            Ok(response) => response,
            Err(_) => {
                // TODO: Should there be more specialized handling for different
                // kinds of errors
                return Err(Error::library_reset(stream_id, Reason::PROTOCOL_ERROR));
            }
        };

        *response.headers_mut() = fields;

        Ok(response)
    }
}
