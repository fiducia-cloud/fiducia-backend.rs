//! Live customer sync streams: the WebSocket upgrade and SSE fallback that
//! push change-notification frames to the portal, plus their shared event
//! envelope helpers. Extracted from main.rs.

use super::*;

pub(crate) async fn customer_ws(
    State(config): State<AppConfig>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(response) = config.authenticator.authenticate(&headers).await {
        return response;
    }
    ws.on_upgrade(customer_ws_stream)
}

pub(crate) async fn customer_events(
    State(config): State<AppConfig>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = config.authenticator.authenticate(&headers).await {
        return response;
    }
    let stream = async_stream::stream! {
        yield Ok::<Event, Infallible>(stream_event("connected", 0));

        let mut interval = tokio::time::interval(Duration::from_secs(STREAM_HEARTBEAT_SECS));
        let mut sequence = 1_u64;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    yield Ok::<Event, Infallible>(stream_event("refresh", sequence));
                    sequence = sequence.saturating_add(1);
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(STREAM_HEARTBEAT_SECS))
                .text("keepalive"),
        )
        .into_response()
}

pub(crate) async fn customer_ws_stream(mut socket: WebSocket) {
    let initial = stream_payload("connected", 0, "websocket").to_string();
    if socket.send(Message::Text(initial)).await.is_err() {
        return;
    }

    let mut interval = tokio::time::interval(Duration::from_secs(STREAM_HEARTBEAT_SECS));
    let mut sequence = 1_u64;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let payload = stream_payload("refresh", sequence, "websocket").to_string();
                sequence = sequence.saturating_add(1);
                if socket.send(Message::Text(payload)).await.is_err() {
                    return;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) if text.eq_ignore_ascii_case("ping") => {
                        if socket.send(Message::Text(stream_payload("pong", sequence, "websocket").to_string())).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return,
                }
            }
        }
    }
}

pub(crate) fn stream_event(kind: &str, sequence: u64) -> Event {
    Event::default()
        .event("fiducia-refresh")
        .id(sequence.to_string())
        .data(stream_payload(kind, sequence, "sse").to_string())
}

pub(crate) fn stream_payload(kind: &str, sequence: u64, transport: &str) -> serde_json::Value {
    json!({
        "kind": kind,
        "sequence": sequence,
        "transport": transport,
        "event": "fiducia:refresh",
        "at_ms": unix_epoch_ms(),
        "fragments": { "summary": summary_markup().into_string() },
    })
}

pub(crate) fn unix_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
