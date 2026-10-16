use futures::StreamExt;
use h2_support::prelude::*;
use tokio::sync::oneshot;

fn trailers(kind: &str) -> frame::Headers {
    let mut pseudo = frame::Pseudo::default();
    match kind {
        "method" => pseudo.method = Some(Method::GET),
        "scheme" => pseudo.scheme = Some(util::byte_str("https")),
        "authority" => pseudo.authority = Some(util::byte_str("example.com")),
        "path" => pseudo.path = Some(util::byte_str("/other")),
        "protocol" => pseudo.protocol = Some(Protocol::from_static("websocket")),
        "status" => pseudo.status = Some(StatusCode::OK),
        "oversized" => {
            return frames::headers(1)
                .field("x-large", "x".repeat(512))
                .eos()
                .into()
        }
        _ => unreachable!(),
    }
    frames::headers(1).pseudo(pseudo).eos().into()
}

async fn expect_body_error(mut body: RecvStream) {
    loop {
        match body
            .data()
            .await
            .expect("malformed trailers must not complete the body")
        {
            Ok(bytes) => body.flow_control().release_capacity(bytes.len()).unwrap(),
            Err(error) => {
                assert_eq!(error.reason(), Some(Reason::PROTOCOL_ERROR));
                break;
            }
        }
    }
}

#[tokio::test]
async fn malformed_request_trailers_reset_before_closing_receive_side() {
    for kind in [
        "method",
        "scheme",
        "authority",
        "path",
        "protocol",
        "status",
        "oversized",
    ] {
        let (io, mut peer) = mock::new();
        let peer = async move {
            peer.assert_server_handshake().await;
            peer.send_frame(frames::headers(1).request("POST", "https://example.com/"))
                .await;
            peer.recv_frame(frames::headers(1).response(200).eos())
                .await;
            peer.send_frame(frames::data(1, "body")).await;
            peer.send_frame(trailers(kind)).await;
            peer.recv_frame(frames::reset(1).protocol_error()).await;
            peer.send_frame(
                frames::headers(3)
                    .request("GET", "https://example.com/")
                    .eos(),
            )
            .await;
            peer.recv_frame(frames::headers(3).response(200).eos())
                .await;
        };
        let server = async move {
            let mut connection = server::Builder::new()
                .max_header_list_size(256)
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let (request, mut response) = connection.next().await.unwrap().unwrap();
            response.send_response(Response::new(()), true).unwrap();
            let (_, sibling) =
                join(expect_body_error(request.into_body()), connection.next()).await;
            let (_, mut response) = sibling.unwrap().unwrap();
            response.send_response(Response::new(()), true).unwrap();
            assert!(connection.next().await.is_none());
        };
        tokio::time::timeout(Duration::from_secs(5), join(peer, server))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn malformed_response_trailers_reset_before_closing_receive_side() {
    for kind in [
        "method",
        "scheme",
        "authority",
        "path",
        "protocol",
        "status",
        "oversized",
    ] {
        let (io, mut peer) = mock::new();
        let (head_tx, head_rx) = oneshot::channel();
        let peer = async move {
            peer.assert_client_handshake().await;
            peer.recv_frame(
                frames::headers(1)
                    .request("GET", "https://example.com/")
                    .eos(),
            )
            .await;
            peer.send_frame(frames::headers(1).response(200)).await;
            head_rx.await.unwrap();
            peer.send_frame(frames::data(1, "body")).await;
            peer.send_frame(trailers(kind)).await;
            peer.recv_frame(frames::reset(1).protocol_error()).await;
            peer.recv_frame(
                frames::headers(3)
                    .request("GET", "https://example.com/")
                    .eos(),
            )
            .await;
            peer.send_frame(frames::headers(3).response(200).eos())
                .await;
        };
        let client = async move {
            let (mut client, mut connection) = client::Builder::new()
                .max_header_list_size(256)
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let response = connection
                .drive(client.get("https://example.com/"))
                .await
                .unwrap();
            head_tx.send(()).unwrap();
            connection
                .drive(expect_body_error(response.into_body()))
                .await;
            let response = connection
                .drive(client.get("https://example.com/"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.body().is_end_stream());
            drop(client);
            connection.await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), join(peer, client))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn raw_path_fragments_are_rejected_but_encoded_hashes_survive() {
    for path in [
        "/admin#fragment",
        "/admin?query#fragment",
        "/admin#\r\ninvalid",
    ] {
        let (io, mut peer) = mock::new();
        let mut headers: frame::Headers = frames::headers(1)
            .request("GET", "https://example.com/")
            .eos()
            .into();
        headers.pseudo_mut().path = Some(util::byte_str(path));
        let peer = async move {
            peer.assert_server_handshake().await;
            peer.send_frame(headers).await;
            peer.recv_frame(frames::reset(1).protocol_error()).await;
            peer.send_frame(
                frames::headers(3)
                    .request("GET", "https://example.com/admin%23fragment")
                    .eos(),
            )
            .await;
            peer.recv_frame(frames::headers(3).response(200).eos())
                .await;
        };
        let server = async move {
            let mut connection = server::handshake(io).await.unwrap();
            let (request, mut response) = connection.next().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/admin%23fragment");
            response.send_response(Response::new(()), true).unwrap();
            assert!(connection.next().await.is_none());
        };
        tokio::time::timeout(Duration::from_secs(5), join(peer, server))
            .await
            .unwrap();
    }
}
