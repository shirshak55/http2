//! Extensions specific to the HTTP/2 protocol.

use crate::frame::{Priority, PseudoId, PseudoOrder, StreamDependency};
use crate::hpack::BytesStr;

use bytes::Bytes;
use http::HeaderName;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Sends the request it is inserted into as an [Extended CONNECT Protocol] request with
/// this `:protocol`: its `:method` is CONNECT, whatever method the request has. Lets a
/// caller that treats a CONNECT request as an upgrade send an extended CONNECT as an
/// ordinary request, its body the stream's DATA and its response's body the DATA back.
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Debug)]
pub struct ExtendedConnect(pub Protocol);

/// Keeps the flow-control windows of the request it is inserted into the connection's own:
/// its receive window grows by the data the caller releases, to no more than 1 MiB once the
/// initial window is spent, and never by the WINDOW_UPDATEs a
/// [`Control`](crate::client::Control) relays for it, and the peer's WINDOW_UPDATEs for it
/// aren't relayed. For a stream whose DATA the caller relays changed, whose peers' grants
/// are for the data the caller sent each, not the data the other sent.
#[derive(Clone, Copy, Debug)]
pub struct OwnWindow;

/// The names of a message's header fields in the order its header block carries them,
/// repeats included, which a `HeaderMap` loses by grouping a repeated name's values.
///
/// http2 inserts one into each request and response it receives. A request or response
/// sent with one is encoded in its order: each listed name takes the next value of that
/// name, and values it doesn't list follow in map order. Trailers carry theirs beside
/// the map, through [`RecvStream::poll_trailers_with_order`] and
/// [`SendStream::send_trailers_with_order`].
///
/// [`RecvStream::poll_trailers_with_order`]: crate::RecvStream::poll_trailers_with_order
/// [`SendStream::send_trailers_with_order`]: crate::SendStream::send_trailers_with_order
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeaderOrder(pub Vec<HeaderName>);

/// Refuses the pushes a server promises on the request carrying it: each promised stream is
/// reset with `CANCEL` as its PUSH_PROMISE arrives, as a client rejects a push it doesn't
/// want (RFC 9113 §8.4.2). For a connection whose SETTINGS allow push (an exact SETTINGS
/// frame replayed) but which takes none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefusePushes;

/// The pseudo-header fields of the request carrying it to send as never-indexed literals
/// (RFC 7541 §6.2.3), as a field whose value is marked sensitive is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NeverIndexedPseudo(pub Vec<PseudoId>);

/// How a header block goes on the wire: its HPACK dynamic table size updates and each
/// field's representation (RFC 7541), and how its HEADERS frame and the CONTINUATION
/// frames after it carry it.
///
/// A request sent with one has its header block encoded as it says, as far as the
/// connection's own table allows: each field takes the representation of the first field
/// it lists by that name and value not taken yet, else by that name, and a representation
/// naming a table entry the connection's table doesn't hold at that index names one that
/// does, or goes as a literal entering the table; fields it doesn't list, and size updates
/// above the peer's limit, go as the connection would send them. The HEADERS frame takes
/// its padding, and the fragments their lengths, as far as the block and the peer's frame
/// size allow.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HeaderBlockEncoding {
    /// The dynamic table size updates at its start, in order (RFC 7541 §6.3).
    pub size_updates: Vec<usize>,
    /// Its fields in block order, pseudo-header fields first.
    pub fields: Vec<EncodedField>,
    /// The HEADERS frame's pad length, when it carried the PADDED flag.
    pub padding: Option<u8>,
    /// The lengths of the block's fragments: the HEADERS frame's, then each
    /// CONTINUATION frame's.
    pub fragments: Vec<usize>,
}

/// A header field as a header block carried it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EncodedField {
    /// Its name, a pseudo-header field's with its colon.
    pub name: Bytes,
    /// Its value.
    pub value: Bytes,
    /// How it went.
    pub representation: FieldRepresentation,
}

/// How a header field went in an HPACK header block (RFC 7541 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldRepresentation {
    /// By the index of its static or dynamic table entry (§6.1).
    Indexed(usize),
    /// As a literal (§6.2).
    Literal {
        /// Whether, and how, it enters the dynamic table.
        indexing: LiteralIndexing,
        /// The index of the table entry naming it, or `None` for a literal name.
        name_index: Option<usize>,
        /// Whether its literal name is Huffman-coded.
        name_huffman: bool,
        /// Whether its value is Huffman-coded.
        value_huffman: bool,
    },
}

/// How a literal header field touches the HPACK dynamic table (RFC 7541 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiteralIndexing {
    /// It enters the table (§6.2.1).
    Incremental,
    /// It doesn't (§6.2.2).
    Without,
    /// It doesn't, nor may an intermediary encoding it again add it (§6.2.3).
    Never,
}

/// A DATA frame a [`BodyLayout`] holds: one of a body another connection received that
/// carried padding or no data or ended the stream (the others carried data unpadded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataFrame {
    /// How many DATA frames carrying data went before it on its stream.
    pub index: u64,
    /// The length of its data.
    pub len: usize,
    /// Its pad length, when it carried the PADDED flag.
    pub padding: Option<u8>,
    /// The END_STREAM flag.
    pub end_stream: bool,
}

/// How a body goes on the wire past its header block, as another connection received
/// it: its DATA frames that carried padding or no data or ended the stream, and how its
/// trailers' header block went.
///
/// A request sent with a [`SendBodyLayout`] goes so: ahead of each chunk of its body go
/// the empty DATA frames the layout has there, the chunk takes its frame's padding when
/// their lengths match, and its end goes in a frame of its own when the layout's did. A
/// padded frame the peer's frame size or flow control can't take whole goes split, data
/// first, its padding kept. Its trailers' header block goes as [`HeaderBlockEncoding`]
/// says.
pub trait BodyLayout: Send + Sync {
    /// Removes and returns the DATA frames it holds that went no later than the DATA
    /// frame carrying data at `through`, or every one given `None`.
    fn take(&self, through: Option<u64>) -> Vec<DataFrame>;

    /// Takes how the trailers' header block went, once it arrived.
    fn take_trailers(&self) -> Option<HeaderBlockEncoding>;

    /// Tells that `octets` of the window the padding (its pad length field included) of
    /// the frames [`Self::take`] gave would take won't be sent: padding the stream's window
    /// or the frame size lacked room for, and that of frames whose data didn't go as they
    /// did, or that came after the body's end.
    fn padding_unsent(&self, octets: usize) {
        let _ = octets;
    }
}

/// How a response went on the wire: its header block, and its body, kept as it arrives.
///
/// A client built with [`record_frames`](crate::client::Builder::record_frames) inserts
/// one into each response.
#[derive(Clone, Debug)]
pub struct ReceivedResponse {
    /// How its header block went.
    pub encoding: HeaderBlockEncoding,
    /// How its body goes, kept as it arrives.
    pub body: BodyFrames,
}

/// How a message's body went on the wire past its header block, kept as it arrives:
/// each DATA frame that carried padding or no data or ended the stream (the others
/// carried data unpadded), and how its trailers' header block went. Clones share it.
#[derive(Clone, Debug, Default)]
pub struct BodyFrames(Arc<Mutex<ReceivedBody>>);

#[derive(Debug, Default)]
struct ReceivedBody {
    /// How many DATA frames carrying data arrived.
    data_frames: u64,
    /// The DATA frames kept and not yet taken.
    frames: std::collections::VecDeque<DataFrame>,
    trailers: Option<HeaderBlockEncoding>,
}

/// The most DATA frames a [`BodyFrames`] holds untaken; it drops any more.
const MAX_KEPT_DATA_FRAMES: usize = 1024;

impl BodyFrames {
    fn lock(&self) -> MutexGuard<'_, ReceivedBody> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push_data(&self, len: usize, padding: Option<u8>, end_stream: bool) {
        let mut body = self.lock();
        let index = body.data_frames;
        if len > 0 {
            body.data_frames += 1;
        }
        if (padding.is_some() || len == 0 || end_stream) && body.frames.len() < MAX_KEPT_DATA_FRAMES
        {
            body.frames.push_back(DataFrame {
                index,
                len,
                padding,
                end_stream,
            });
        }
    }

    pub(crate) fn set_trailers(&self, encoding: HeaderBlockEncoding) {
        self.lock().trailers = Some(encoding);
    }

    /// Removes and returns the DATA frames kept so far that went no later than the DATA
    /// frame carrying data at `through`, or every one kept given `None`.
    pub fn take(&self, through: Option<u64>) -> Vec<DataFrame> {
        let mut body = self.lock();
        let end = match through {
            Some(through) => body.frames.partition_point(|frame| frame.index <= through),
            None => body.frames.len(),
        };
        body.frames.drain(..end).collect()
    }

    /// Takes how the trailers' header block went, once it arrived.
    pub fn take_trailers(&self) -> Option<HeaderBlockEncoding> {
        self.lock().trailers.take()
    }
}

/// A request extension sending its body as a [`BodyLayout`] says.
#[derive(Clone)]
pub struct SendBodyLayout(pub Arc<dyn BodyLayout>);

impl fmt::Debug for SendBodyLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("SendBodyLayout(..)")
    }
}

/// How to send the HEADERS frame of the request carrying it, in place of the connection's
/// [`headers_pseudo_order`] and [`headers_stream_dependency`].
///
/// [`headers_pseudo_order`]: crate::client::Builder::headers_pseudo_order
/// [`headers_stream_dependency`]: crate::client::Builder::headers_stream_dependency
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeadersFrameOptions {
    /// The pseudo-header fields' order; `None` keeps the connection's.
    pub pseudo_order: Option<PseudoOrder>,
    /// The priority fields (dependency, weight, exclusive flag); `None` sends the frame
    /// without the PRIORITY flag.
    pub priority: Option<StreamDependency>,
    /// The id the request's stream had on the connection `priority` was recorded on, whose
    /// stream ids its dependency and the PRIORITY frames of `leading` and `following` name:
    /// the recorded request's own id names the stream opened here, a request's recorded
    /// earlier names the stream opened here for it (when none was, a dependency on it is on
    /// the root and a PRIORITY frame for it isn't sent), ids below the first request's
    /// (`first_recorded_stream_id`, else the first recorded here) name the same idle
    /// streams, and ids above the request's own lie as far above the stream opened here. A
    /// dependency renumbered to the stream itself is on the root.
    pub recorded_stream_id: Option<u32>,
    /// The id the first request's stream had on the connection the request was recorded
    /// on, the ids below which name idle streams: a connection whose first request is that
    /// one opens each request's stream on its `recorded_stream_id`, as long as that id lies
    /// past the streams it opened, so its streams are numbered as recorded.
    pub first_recorded_stream_id: Option<u32>,
    /// PRIORITY frames to send right before the HEADERS frame, in order.
    pub leading: Vec<Priority>,
    /// Frames to send right after the HEADERS frame, in order, before any DATA.
    pub following: Vec<FollowingFrame>,
}

/// A frame a client connection sends once, after its SETTINGS and right before its first
/// request's HEADERS, in the order given; see
/// [`preface_frames`](crate::client::Builder::preface_frames).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrefaceFrame {
    /// A connection WINDOW_UPDATE; the connection's receive window grows by the increment.
    WindowUpdate(u32),
    /// A PRIORITY frame, its streams numbered as on the connection the first request was
    /// recorded on (see [`HeadersFrameOptions::recorded_stream_id`]).
    Priority(Priority),
    /// A SETTINGS frame of exactly these parameters, `(identifier, value)` in order,
    /// beyond the connection's first; the known ones apply when the peer acknowledges it.
    Settings(Vec<(u16, u32)>),
    /// A PING carrying this payload; its acknowledgement is ignored.
    Ping([u8; 8]),
    /// A frame of a type HTTP/2 doesn't define, sent as given.
    Unknown(UnknownFrame),
}

/// A frame to send right after a request's HEADERS frame; see
/// [`HeadersFrameOptions::following`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FollowingFrame {
    /// WINDOW_UPDATE on the request's stream; the stream's receive window grows by the
    /// increment (so the peer may send that much more, and the automatic window-update
    /// policy then works from the larger window).
    WindowUpdate(u32),
    /// A PRIORITY frame, its streams numbered as the request's
    /// [`recorded_stream_id`](HeadersFrameOptions::recorded_stream_id) says.
    Priority(Priority),
    /// A frame of a type HTTP/2 doesn't define, on the request's stream when `on_stream`,
    /// else on stream 0, sent as given.
    Unknown {
        /// The frame type.
        kind: u8,
        /// The flags.
        flags: u8,
        /// Whether the frame goes on the request's stream rather than stream 0.
        on_stream: bool,
        /// The payload.
        payload: Bytes,
    },
}

/// A frame of a type HTTP/2 doesn't define, such as a GREASE type, to send as given; see
/// [`PrefaceFrame::Unknown`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownFrame {
    /// The frame type.
    pub kind: u8,
    /// The flags.
    pub flags: u8,
    /// The stream identifier.
    pub stream_id: u32,
    /// The payload.
    pub payload: Bytes,
}

/// The frames a connection sent that shape its HTTP/2 fingerprint, in wire order: every
/// frame but DATA and CONTINUATION (a `Headers` entry stands for its whole header block),
/// up to a limit.
///
/// A client built with [`record_frames`](crate::client::Builder::record_frames) keeps one
/// per connection and hands it to each response inside its [`HeadersFrame`]. Clones share
/// the log, which keeps growing while the connection lives, so a response sees at least
/// every frame up to its request's HEADERS.
#[derive(Clone, Debug)]
pub struct FrameLog(Arc<Mutex<FrameLogInner>>);

#[derive(Debug)]
struct FrameLogInner {
    frames: Vec<LoggedFrame>,
    limit: usize,
    dropped: usize,
}

impl FrameLog {
    pub(crate) fn new(limit: usize) -> Self {
        FrameLog(Arc::new(Mutex::new(FrameLogInner {
            frames: Vec::new(),
            limit,
            dropped: 0,
        })))
    }

    fn lock(&self) -> MutexGuard<'_, FrameLogInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push(&self, frame: LoggedFrame) {
        let mut inner = self.lock();
        if inner.frames.len() < inner.limit {
            inner.frames.push(frame);
        } else {
            inner.dropped += 1;
        }
    }

    /// The frames logged so far, in wire order.
    pub fn frames(&self) -> Vec<LoggedFrame> {
        self.lock().frames.clone()
    }

    /// How many frames were sent after the log reached its limit, and were not logged.
    pub fn dropped(&self) -> usize {
        self.lock().dropped
    }
}

/// The connection preface a client connection's peer sent — its SETTINGS frames, each of
/// which the connection acknowledges and applies itself, and the connection
/// WINDOW_UPDATEs and frames of types HTTP/2 doesn't define among and after them — as
/// [`LoggedFrame`]s in wire order, once the connection received all of it: the peer's
/// SETTINGS ACK or a frame of any other kind ends it (and isn't part of it), as does one
/// past 1,024 frames or 1 MiB of their payloads, or the connection's end (then it holds
/// what arrived: nothing when the peer sent no SETTINGS). Once a caller relays the frames
/// past it (see [`Control::relay_received`](crate::client::Control::relay_received)), it
/// ends as soon as it holds a SETTINGS frame, the frames after going to that caller: a
/// peer acknowledging the connection's SETTINGS only once it got what the relayed peer
/// may send it only past the preface isn't waited for.
///
/// Resolves as soon as it is complete, ahead of any response; see
/// [`Control::received_preface`](crate::client::Control::received_preface).
#[derive(Clone, Debug, Default)]
pub struct ReceivedPreface(Arc<Mutex<ReceivedPrefaceInner>>);

#[derive(Debug, Default)]
struct ReceivedPrefaceInner {
    frames: Vec<LoggedFrame>,
    /// The octets of their payloads.
    octets: usize,
    complete: bool,
    /// Whether a caller relays the frames past it, which ends it once it holds a SETTINGS.
    relayed: bool,
    /// Whether it took the latest frame the connection received.
    took_latest: bool,
    wakers: Vec<Waker>,
}

impl ReceivedPreface {
    fn lock(&self) -> MutexGuard<'_, ReceivedPrefaceInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Feeds it the frames the connection receives (see [`PrefaceRecorder`]).
    pub(crate) fn recorder(&self) -> PrefaceRecorder {
        PrefaceRecorder(self.clone())
    }

    /// Whether the latest frame the connection received is part of it: a relaying caller
    /// doesn't get it.
    pub(crate) fn took_latest(&self) -> bool {
        self.lock().took_latest
    }

    /// Notes that a caller relays the frames past it (see [`Self`]).
    pub(crate) fn relayed(&self) {
        let mut inner = self.lock();
        inner.relayed = true;
        for waker in inner.wakers.drain(..) {
            waker.wake();
        }
    }

    fn complete(&self) {
        let mut inner = self.lock();
        inner.complete = true;
        for waker in inner.wakers.drain(..) {
            waker.wake();
        }
    }
}

impl Future for ReceivedPreface {
    type Output = Vec<LoggedFrame>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.lock();
        if !inner.complete
            && inner.relayed
            && inner
                .frames
                .iter()
                .any(|frame| matches!(frame, LoggedFrame::Settings { ack: false, .. }))
        {
            inner.complete = true;
            for waker in inner.wakers.drain(..) {
                waker.wake();
            }
        }
        if inner.complete {
            return Poll::Ready(inner.frames.clone());
        }
        if !inner.wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            inner.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// How many frames, and octets of their payloads, a [`ReceivedPreface`] holds before the
/// next frame ends it.
const PREFACE_FRAMES: usize = 1024;
const PREFACE_OCTETS: usize = 1 << 20;

/// Records a connection's received frames into its [`ReceivedPreface`] until it is
/// complete; dropped (the connection ended, or the preface is complete), it completes it.
#[derive(Debug)]
pub(crate) struct PrefaceRecorder(ReceivedPreface);

impl PrefaceRecorder {
    /// Records `frame`, received, unless the preface is complete or the frame ends it
    /// (`None` is a frame of a kind not logged, which does); returns whether it took it,
    /// the preface being complete otherwise.
    pub(crate) fn record(&self, frame: Option<&LoggedFrame>) -> bool {
        let mut inner = self.0.lock();
        let octets = match frame {
            Some(LoggedFrame::Settings { ack: false, params }) => Some(params.len() * 6),
            Some(LoggedFrame::WindowUpdate { stream_id: 0, .. }) => Some(4),
            Some(LoggedFrame::Unknown { payload, .. }) => Some(payload.len()),
            _ => None,
        };
        inner.took_latest = match frame.zip(octets) {
            Some((frame, octets))
                if !inner.complete
                    && inner.frames.len() < PREFACE_FRAMES
                    && inner.octets < PREFACE_OCTETS =>
            {
                // A relaying caller waits for it to hold a SETTINGS frame.
                if inner.relayed && matches!(frame, LoggedFrame::Settings { .. }) {
                    for waker in inner.wakers.drain(..) {
                        waker.wake();
                    }
                }
                inner.frames.push(frame.clone());
                inner.octets += octets;
                true
            }
            _ => false,
        };
        let took = inner.took_latest;
        drop(inner);
        if !took {
            self.0.complete();
        }
        took
    }
}

impl Drop for PrefaceRecorder {
    fn drop(&mut self) {
        self.0.complete();
    }
}

/// A frame in a [`FrameLog`], with its fields as sent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoggedFrame {
    /// A SETTINGS frame: every parameter's identifier and value in wire order, unknown
    /// identifiers and repeats included.
    Settings {
        /// The ACK flag.
        ack: bool,
        /// `(identifier, value)` pairs.
        params: Vec<(u16, u32)>,
    },
    /// A WINDOW_UPDATE frame; stream 0 is the connection.
    WindowUpdate {
        /// The stream the update applies to.
        stream_id: u32,
        /// The window size increment.
        increment: u32,
    },
    /// A PRIORITY frame.
    Priority {
        /// The stream the priority applies to.
        stream_id: u32,
        /// The priority it sets.
        priority: StreamPriority,
    },
    /// A HEADERS frame, with any CONTINUATION frames completing its header block.
    Headers {
        /// The stream it opens or continues.
        stream_id: u32,
        /// The END_STREAM flag.
        end_stream: bool,
        /// Its priority fields, when it carries the PRIORITY flag.
        priority: Option<StreamPriority>,
        /// Its pseudo-header fields, in block order.
        pseudo_order: Vec<PseudoHeader>,
    },
    /// A PING frame.
    Ping {
        /// The ACK flag.
        ack: bool,
        /// The opaque data.
        payload: [u8; 8],
    },
    /// A RST_STREAM frame.
    Reset {
        /// The stream reset.
        stream_id: u32,
        /// The error code.
        error_code: u32,
    },
    /// A GOAWAY frame.
    GoAway {
        /// The last stream identifier.
        last_stream_id: u32,
        /// The error code.
        error_code: u32,
        /// The additional debug data.
        debug_data: Bytes,
    },
    /// A frame of a type HTTP/2 doesn't define, such as a GREASE type.
    Unknown {
        /// The frame type.
        kind: u8,
        /// The flags.
        flags: u8,
        /// The stream identifier.
        stream_id: u32,
        /// The payload length.
        length: u32,
        /// The payload.
        payload: Bytes,
    },
}

/// A stream's priority fields as a HEADERS or PRIORITY frame carries them (RFC 7540
/// §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamPriority {
    /// The stream this one depends on.
    pub dependency: u32,
    /// The weight byte as sent: the weight minus one (0 for weight 1, 255 for 256).
    pub weight: u8,
    /// The exclusive flag.
    pub exclusive: bool,
}

/// A pseudo-header field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudoHeader {
    /// `:method`
    Method,
    /// `:scheme`
    Scheme,
    /// `:authority`
    Authority,
    /// `:path`
    Path,
    /// `:protocol`
    Protocol,
    /// `:status`
    Status,
}

/// How a request's HEADERS frame was sent: its stream, priority fields and pseudo-header
/// order, beside its connection's [`FrameLog`].
///
/// A client built with [`record_frames`](crate::client::Builder::record_frames) inserts
/// one into each response.
#[derive(Clone, Debug)]
pub struct HeadersFrame {
    /// The request's stream identifier.
    pub stream_id: u32,
    /// Its priority fields, when the HEADERS frame carried the PRIORITY flag.
    pub priority: Option<StreamPriority>,
    /// Its pseudo-header fields, in block order.
    pub pseudo_order: Vec<PseudoHeader>,
    /// The frames its connection sent.
    pub connection: FrameLog,
    /// The frames its connection received (the server's SETTINGS, WINDOW_UPDATE and any
    /// other but DATA, in order).
    pub received: FrameLog,
}
