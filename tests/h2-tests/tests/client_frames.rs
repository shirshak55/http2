use h2::ext::{
    FollowingFrame, HeadersFrame, HeadersFrameOptions, LoggedFrame, PseudoHeader, StreamPriority,
    UnknownFrame,
};
use h2::frame::{Priorities, Priority, PseudoId, PseudoOrder, StreamDependency};
use h2_support::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// A frame as read off the wire: type, flags, stream identifier and payload.
type RawFrame = (u8, u8, u32, Vec<u8>);

async fn read_frame(io: &mut DuplexStream) -> RawFrame {
    let mut head = [0; 9];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut head))
        .await
        .expect("timed out reading a frame")
        .unwrap();
    let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
    io.read_exact(&mut payload).await.unwrap();
    let stream_id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
    (head[3], head[4], stream_id, payload)
}

/// Reads the client preface and SETTINGS frame, which it returns, and sends the server's
/// SETTINGS and the ACK.
async fn accept(io: &mut DuplexStream) -> RawFrame {
    let mut preface = [0; 24];
    io.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface[..], MAGIC_PREFACE);
    let settings = read_frame(io).await;
    io.write_all(frames::SETTINGS).await.unwrap();
    io.write_all(frames::SETTINGS_ACK).await.unwrap();
    settings
}

/// Reads the next `n` frames but SETTINGS.
async fn read_frames(io: &mut DuplexStream, n: usize) -> Vec<RawFrame> {
    let mut frames = Vec::new();
    while frames.len() < n {
        let frame = read_frame(io).await;
        if frame.0 != 4 {
            frames.push(frame);
        }
    }
    frames
}

async fn send_response(io: &mut DuplexStream, stream_id: u32, end_stream: bool) {
    let flags = if end_stream { 0x5 } else { 0x4 };
    let mut frame = vec![0, 0, 1, 1, flags];
    frame.extend(stream_id.to_be_bytes());
    // `:status: 200`
    frame.push(0x88);
    io.write_all(&frame).await.unwrap();
}

fn get() -> Request<()> {
    Request::get("https://example.com/").body(()).unwrap()
}

fn with_following(mut request: Request<()>, following: Vec<FollowingFrame>) -> Request<()> {
    request.extensions_mut().insert(HeadersFrameOptions {
        following,
        ..Default::default()
    });
    request
}

fn priority_on_3() -> Priorities {
    Priorities::builder()
        .push(Priority::new(
            3.into(),
            StreamDependency::new(0.into(), 200, false),
        ))
        .build()
}

#[tokio::test]
async fn unknown_frames_sent_once_before_first_headers() {
    h2_support::trace_init!();
    let (io, mut srv) = tokio::io::duplex(1 << 20);

    let srv = async move {
        accept(&mut srv).await;
        // Each request's PRIORITY frame, then the unknown frames right ahead of the
        // first request's HEADERS, which still goes out before the second's.
        let frames = read_frames(&mut srv, 6).await;
        let priority = (2, 0, 3, vec![0, 0, 0, 0, 200]);
        assert_eq!(frames[0], priority);
        assert_eq!(frames[1], priority);
        assert_eq!(frames[2], (0x0b, 0x1, 0, vec![1, 2, 3]));
        assert_eq!(frames[3], (0xfa, 0x0, 9, vec![]));
        assert_eq!((frames[4].0, frames[4].2), (1, 5));
        assert_eq!((frames[5].0, frames[5].2), (1, 7));
        send_response(&mut srv, 5, true).await;
        send_response(&mut srv, 7, true).await;
        srv
    };

    let h2 = async move {
        let (mut client, mut h2) = client::Builder::new()
            .initial_stream_id(5)
            .priorities(priority_on_3())
            .unknown_frames([
                UnknownFrame {
                    kind: 0x0b,
                    flags: 0x1,
                    stream_id: 0,
                    payload: Bytes::from_static(&[1, 2, 3]),
                },
                UnknownFrame {
                    kind: 0xfa,
                    flags: 0x0,
                    stream_id: 9,
                    payload: Bytes::new(),
                },
            ])
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (first, _) = client.send_request(get(), true).unwrap();
        let (second, _) = client.send_request(get(), true).unwrap();
        h2.drive(first).await.unwrap();
        h2.drive(second).await.unwrap();
    };

    join(srv, h2).await;
}

#[tokio::test]
async fn priorities_once_sent_before_first_headers_in_stream_order() {
    h2_support::trace_init!();
    let (io, mut srv) = tokio::io::duplex(1 << 20);

    let srv = async move {
        accept(&mut srv).await;
        // The PRIORITY frame once, right ahead of the first request's HEADERS, which
        // still goes out before the second's.
        let frames = read_frames(&mut srv, 3).await;
        assert_eq!(frames[0], (2, 0, 3, vec![0, 0, 0, 0, 200]));
        assert_eq!((frames[1].0, frames[1].2), (1, 5));
        assert_eq!((frames[2].0, frames[2].2), (1, 7));
        send_response(&mut srv, 5, true).await;
        send_response(&mut srv, 7, true).await;
        srv
    };

    let h2 = async move {
        let (mut client, mut h2) = client::Builder::new()
            .initial_stream_id(5)
            .priorities(priority_on_3())
            .priorities_once(true)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (first, _) = client.send_request(get(), true).unwrap();
        let (second, _) = client.send_request(get(), true).unwrap();
        h2.drive(first).await.unwrap();
        h2.drive(second).await.unwrap();
    };

    join(srv, h2).await;
}

#[tokio::test]
async fn following_window_update_sent_after_headers_grows_stream_window() {
    h2_support::trace_init!();
    let (io, mut srv) = tokio::io::duplex(1 << 20);
    const BODY: usize = 5 * 16_384;

    let srv = async move {
        accept(&mut srv).await;
        let frames = read_frames(&mut srv, 3).await;
        let connection_increment = (1u32 << 20) - 65_535;
        assert_eq!(
            frames[0],
            (8, 0, 0, connection_increment.to_be_bytes().to_vec())
        );
        assert_eq!((frames[1].0, frames[1].2), (1, 1));
        assert_eq!(frames[2], (8, 0, 1, (1u32 << 16).to_be_bytes().to_vec()));

        // More than the stream's initial window.
        send_response(&mut srv, 1, false).await;
        for i in 0..5 {
            let flags = if i == 4 { 0x1 } else { 0x0 };
            srv.write_all(&[0x00, 0x40, 0x00, 0, flags, 0, 0, 0, 1])
                .await
                .unwrap();
            srv.write_all(&[0; 16_384]).await.unwrap();
        }
        srv
    };

    let h2 = async move {
        let (mut client, mut h2) = client::Builder::new()
            .initial_connection_window_size(1 << 20)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let request = with_following(get(), vec![FollowingFrame::WindowUpdate(1 << 16)]);
        let (response, _) = client.send_request(request, true).unwrap();
        let mut body = h2.drive(response).await.unwrap().into_body();
        let mut len = 0;
        while let Some(chunk) = h2.drive(body.data()).await {
            len += chunk.unwrap().len();
        }
        assert_eq!(len, BODY);
    };

    join(srv, h2).await;
}

#[tokio::test]
async fn following_unknown_frames_sent_after_headers_before_data() {
    h2_support::trace_init!();
    let (io, mut srv) = tokio::io::duplex(1 << 20);

    let srv = async move {
        accept(&mut srv).await;
        let frames = read_frames(&mut srv, 4).await;
        assert_eq!((frames[0].0, frames[0].2), (1, 1));
        assert_eq!(frames[1], (0xfa, 0x3, 1, b"ab".to_vec()));
        assert_eq!(frames[2], (0xfb, 0x0, 0, vec![]));
        assert_eq!(frames[3], (0, 0x1, 1, b"hello".to_vec()));
        send_response(&mut srv, 1, true).await;
        srv
    };

    let h2 = async move {
        let (mut client, mut h2) = client::handshake(io).await.unwrap();
        let request = with_following(
            Request::post("https://example.com/").body(()).unwrap(),
            vec![
                FollowingFrame::Unknown {
                    kind: 0xfa,
                    flags: 0x3,
                    on_stream: true,
                    payload: Bytes::from_static(b"ab"),
                },
                FollowingFrame::Unknown {
                    kind: 0xfb,
                    flags: 0x0,
                    on_stream: false,
                    payload: Bytes::new(),
                },
            ],
        );
        let (response, mut stream) = client.send_request(request, false).unwrap();
        stream
            .send_data(Bytes::from_static(b"hello"), true)
            .unwrap();
        h2.drive(response).await.unwrap();
    };

    join(srv, h2).await;
}

#[tokio::test]
async fn following_window_update_rejects_invalid_increment() {
    h2_support::trace_init!();
    let (io, _srv) = tokio::io::duplex(1 << 20);
    let (mut client, _h2) = client::handshake(io).await.unwrap();

    for increment in [0, (1 << 31) - 1] {
        let request = with_following(get(), vec![FollowingFrame::WindowUpdate(increment)]);
        let err = client.send_request(request, true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "user error: invalid WINDOW_UPDATE increment"
        );
    }
}

#[tokio::test]
async fn record_frames_logs_sent_frames_and_request_headers() {
    h2_support::trace_init!();
    let (io, mut srv) = tokio::io::duplex(1 << 20);
    let params = vec![(1, 65_536), (0x0a0a, 0), (4, 6_291_456), (6, 262_144)];
    let priority = StreamPriority {
        dependency: 0,
        weight: 255,
        exclusive: true,
    };
    let pseudo_order = vec![
        PseudoHeader::Method,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
    ];

    let wire_params = params.clone();
    let srv = async move {
        let settings = accept(&mut srv).await;
        let sent: Vec<(u16, u32)> = settings
            .3
            .chunks_exact(6)
            .map(|p| {
                (
                    u16::from_be_bytes([p[0], p[1]]),
                    u32::from_be_bytes([p[2], p[3], p[4], p[5]]),
                )
            })
            .collect();
        assert_eq!(sent, wire_params);
        let frames = read_frames(&mut srv, 4).await;
        assert_eq!(frames[0], (8, 0, 0, 15_663_105u32.to_be_bytes().to_vec()));
        assert_eq!(frames[1], (2, 0, 3, vec![0, 0, 0, 0, 200]));
        assert_eq!(frames[2], (0x0b, 0x0, 0, vec![7]));
        assert_eq!((frames[3].0, frames[3].1, frames[3].2), (1, 0x25, 5));
        assert_eq!(&frames[3].3[..5], &[0x80, 0, 0, 0, 255]);
        send_response(&mut srv, 5, true).await;
        srv
    };

    let expected_order = pseudo_order.clone();
    let h2 = async move {
        let (mut client, mut h2) = client::Builder::new()
            .record_frames(16)
            .settings_frame(params.clone())
            .initial_connection_window_size(15_728_640)
            .initial_stream_id(5)
            .priorities(priority_on_3())
            .unknown_frames([UnknownFrame {
                kind: 0x0b,
                flags: 0x0,
                stream_id: 0,
                payload: Bytes::from_static(&[7]),
            }])
            .headers_pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                        PseudoId::Path,
                    ])
                    .build(),
            )
            .headers_stream_dependency(StreamDependency::new(0.into(), 255, true))
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (response, _) = client.send_request(get(), true).unwrap();
        let response = h2.drive(response).await.unwrap();

        let sent = response.extensions().get::<HeadersFrame>().unwrap();
        assert_eq!(sent.stream_id, 5);
        assert_eq!(sent.priority, Some(priority));
        assert_eq!(sent.pseudo_order, expected_order);

        let (acks, frames): (Vec<_>, Vec<_>) = sent
            .connection
            .frames()
            .into_iter()
            .partition(|frame| matches!(frame, LoggedFrame::Settings { ack: true, .. }));
        assert_eq!(
            frames,
            [
                LoggedFrame::Settings { ack: false, params },
                LoggedFrame::WindowUpdate {
                    stream_id: 0,
                    increment: 15_663_105,
                },
                LoggedFrame::Priority {
                    stream_id: 3,
                    priority: StreamPriority {
                        dependency: 0,
                        weight: 200,
                        exclusive: false,
                    },
                },
                LoggedFrame::Unknown {
                    kind: 0x0b,
                    flags: 0x0,
                    stream_id: 0,
                    length: 1,
                    payload: Bytes::from_static(&[7]),
                },
                LoggedFrame::Headers {
                    stream_id: 5,
                    end_stream: true,
                    priority: Some(priority),
                    pseudo_order,
                },
            ]
        );
        assert!(acks.iter().all(|ack| *ack
            == LoggedFrame::Settings {
                ack: true,
                params: vec![],
            }));
        assert_eq!(sent.connection.dropped(), 0);
    };

    join(srv, h2).await;
}
