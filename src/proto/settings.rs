use crate::error::Reason;
use crate::proto::*;
use crate::tracing;
use std::collections::VecDeque;
use std::task::{Context, Poll};

#[derive(Debug)]
pub(crate) struct Settings {
    /// Our SETTINGS to send to the remote when the socket is ready, in order. Those sent
    /// await their acknowledgements in the codec, which applies them in the order sent;
    /// several may await one at once (RFC 9113 §6.5.3).
    to_send: VecDeque<frame::Settings>,
    /// Received SETTINGS frame pending processing, and whether it was relayed, which
    /// leaves its ACK to the relayed peer (see `Control::relay_received`), and applying it
    /// to when that ACK goes out. Otherwise the ACK must be written to the socket first then
    /// the settings applied **before** receiving any further frames.
    remote: Option<(frame::Settings, bool)>,
    /// Whether the connection has received the initial SETTINGS frame from the
    /// remote peer.
    has_received_remote_initial_settings: bool,
}

impl Settings {
    pub(crate) fn new() -> Self {
        Settings {
            // The initial local SETTINGS were flushed during the handshake, through the
            // codec, which awaits their acknowledgement.
            to_send: VecDeque::new(),
            remote: None,
            has_received_remote_initial_settings: false,
        }
    }

    /// Handles a received SETTINGS frame; whether it acknowledged one the connection didn't
    /// send of its own accord (see `frame::Settings::set_own`).
    pub(crate) fn recv_settings<T, B, C, P>(
        &mut self,
        frame: frame::Settings,
        relayed: bool,
        codec: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Result<bool, Error>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if frame.is_ack() {
            match codec.take_unacked_settings() {
                Some(local) => {
                    tracing::debug!("received settings ACK; applying {:?}", local);

                    if let Some(max) = local.max_frame_size() {
                        codec.set_max_recv_frame_size(max as usize);
                    }

                    if let Some(max) = local.max_header_list_size() {
                        codec.set_max_recv_header_list_size(max as usize);
                    }

                    if let Some(val) = local.header_table_size() {
                        codec.set_recv_header_table_size(val as usize);
                    }

                    streams.apply_local_settings(&local)?;
                    Ok(!local.is_own())
                }
                None => {
                    // We haven't sent any SETTINGS frames to be ACKed, so
                    // this is very bizarre! Remote is either buggy or malicious.
                    proto_err!(conn: "received unexpected settings ack");
                    Err(Error::library_go_away(Reason::PROTOCOL_ERROR))
                }
            }
        } else {
            // We always ACK before reading more frames, so `remote` should
            // always be none!
            assert!(self.remote.is_none());
            self.remote = Some((frame, relayed));
            Ok(false)
        }
    }

    /// Queues a SETTINGS frame to send, whatever SETTINGS sent before await their
    /// acknowledgement.
    pub(crate) fn send_settings(&mut self, mut frame: frame::Settings) {
        assert!(!frame.is_ack());
        frame.set_own();
        tracing::trace!("queue to send local settings: {:?}", frame);
        self.to_send.push_back(frame);
    }

    /// Sets `true` to `self.has_received_remote_initial_settings`.
    /// Returns `true` if this method is called for the first time.
    /// (i.e. it is the initial SETTINGS frame from the remote peer)
    fn mark_remote_initial_settings_as_received(&mut self) -> bool {
        let has_received = self.has_received_remote_initial_settings;
        self.has_received_remote_initial_settings = true;
        !has_received
    }

    pub(crate) fn poll_send<T, B, C, P>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Poll<Result<(), Error>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if let Some((settings, relayed)) = self.remote.clone() {
            let is_initial = self.mark_remote_initial_settings_as_received();
            if relayed {
                // It applies as the relayed peer's acknowledgement goes out.
                streams.as_dyn().await_relayed_ack(settings);
            } else {
                if !streams.defer_settings_ack() {
                    if !dst.poll_ready(cx)?.is_ready() {
                        return Poll::Pending;
                    }

                    // Create an ACK settings frame
                    let frame = frame::Settings::ack();

                    // Buffer the settings frame
                    dst.buffer(frame.into()).expect("invalid settings frame");
                }

                tracing::trace!("ACK sent or deferred; applying settings");

                streams.apply_remote_settings(&settings, is_initial)?;

                if let Some(val) = settings.header_table_size() {
                    dst.set_send_header_table_size(val as usize);
                }

                if let Some(val) = settings.max_frame_size() {
                    dst.set_max_send_frame_size(val as usize);
                }
            }
        }

        self.remote = None;

        while let Some(settings) = self.to_send.front() {
            if !dst.poll_ready(cx)?.is_ready() {
                return Poll::Pending;
            }

            // Buffer the settings frame
            dst.buffer(settings.clone().into())
                .expect("invalid settings frame");
            tracing::trace!("local settings sent; waiting for ack: {:?}", settings);
            self.to_send.pop_front();
        }

        Poll::Ready(Ok(()))
    }
}
