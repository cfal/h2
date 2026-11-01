use futures::StreamExt;
use h2_support::prelude::*;

#[tokio::test]
async fn promised_raw_path_fragments_are_rejected_but_encoded_hashes_survive() {
    for path in ["/admin#fragment", "/admin?query#\r\ninvalid"] {
        let (io, mut peer) = mock::new();
        let peer = async move {
            peer.assert_client_handshake().await;
            peer.recv_frame(
                frames::headers(1)
                    .request("GET", "https://example.com/")
                    .eos(),
            )
            .await;
            let mut pseudo = frame::Pseudo::request(
                Method::GET,
                "https://example.com/".parse().unwrap(),
                Default::default(),
            );
            pseudo.path = Some(util::byte_str(path));
            peer.send_frame(frame::PushPromise::new(
                1.into(),
                2.into(),
                pseudo,
                HeaderMap::new(),
            ))
            .await;
            peer.recv_frame(frames::reset(2).protocol_error()).await;
            for (id, path) in [(4, "/admin%23fragment"), (6, "/admin?query=%23fragment")] {
                peer.send_frame(
                    frames::push_promise(1, id)
                        .request("GET", format!("https://example.com{}", path)),
                )
                .await;
                peer.send_frame(frames::headers(id).response(200).eos())
                    .await;
            }
            peer.send_frame(frames::headers(1).response(200).eos())
                .await;
        };
        let client = async move {
            let (mut client, mut connection) = client::handshake(io).await.unwrap();
            let (mut response, _) = client
                .send_request(
                    Request::builder()
                        .uri("https://example.com/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut promises = response.push_promises();
            connection
                .drive(async move {
                    for path in ["/admin%23fragment", "/admin?query=%23fragment"] {
                        let promise = promises.next().await.unwrap().unwrap();
                        assert_eq!(
                            promise.request().uri().path_and_query().unwrap().as_str(),
                            path
                        );
                        assert_eq!(
                            promise.into_parts().1.await.unwrap().status(),
                            StatusCode::OK
                        );
                    }
                    assert!(promises.next().await.is_none());
                    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
                })
                .await;
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
        "/admin?query#\r\ninvalid",
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
            for (id, path) in [(3, "/admin%23fragment"), (5, "/admin?query=%23fragment")] {
                peer.send_frame(
                    frames::headers(id)
                        .request("GET", format!("https://example.com{}", path))
                        .eos(),
                )
                .await;
                peer.recv_frame(frames::headers(id).response(200).eos())
                    .await;
            }
        };
        let server = async move {
            let mut connection = server::handshake(io).await.unwrap();
            for path in ["/admin%23fragment", "/admin?query=%23fragment"] {
                let (request, mut response) = connection.next().await.unwrap().unwrap();
                assert_eq!(request.uri().path_and_query().unwrap().as_str(), path);
                response.send_response(Response::new(()), true).unwrap();
            }
            assert!(connection.next().await.is_none());
        };
        tokio::time::timeout(Duration::from_secs(5), join(peer, server))
            .await
            .unwrap();
    }
}
