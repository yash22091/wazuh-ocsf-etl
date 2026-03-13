use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

// ─── ZeroMQ subscriber reader task ───────────────────────────────────────────

pub(crate) async fn zmq_reader_task(
    uri: String,
    tx:  mpsc::Sender<(u64, String)>,
) {
    use zeromq::{Socket, SocketRecv, SubSocket};

    info!("ZeroMQ input: connecting to {uri}");
    loop {
        let mut socket = SubSocket::new();

        if let Err(e) = socket.connect(&uri).await {
            warn!("ZeroMQ connect {uri}: {e:#}. Retrying in 5s…");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        if let Err(e) = socket.subscribe("").await {
            warn!("ZeroMQ subscribe: {e:#}. Retrying in 5s…");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        info!("ZeroMQ input: subscribed to {uri}");

        loop {
            match socket.recv().await {
                Ok(msg) => {
                    let raw = msg.iter()
                        .filter_map(|frame| std::str::from_utf8(frame.as_ref()).ok())
                        .collect::<Vec<_>>()
                        .join("");
                    let trimmed = raw.trim().to_string();
                    if trimmed.is_empty() { continue; }
                    if tx.send((0, trimmed)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    warn!("ZeroMQ recv: {e:#}. Reconnecting in 5s…");
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
