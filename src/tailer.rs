use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader as TokioBufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::state::TailState;

// ─── File tailer ──────────────────────────────────────────────────────────────

pub(crate) struct FileTailer {
    path: PathBuf,
    reader: TokioBufReader<TokioFile>,
    offset: u64,
    inode: u64,
}

impl FileTailer {
    pub(crate) async fn open(path: &Path, offset: u64) -> Result<Self> {
        let inode = std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0);
        let mut file = TokioFile::open(path)
            .await
            .with_context(|| format!("open {}", path.display()))?;
        file.seek(SeekFrom::Start(offset)).await?;
        Ok(Self {
            path: path.to_path_buf(),
            reader: TokioBufReader::with_capacity(256 * 1024, file),
            offset,
            inode,
        })
    }

    pub(crate) async fn next_line(&mut self) -> Result<Option<String>> {
        let mut buf = String::new();
        let n = self.reader.read_line(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        if buf.ends_with('\n') {
            self.offset += n as u64;
            Ok(Some(
                buf.trim_end_matches('\n')
                    .trim_end_matches('\r')
                    .to_string(),
            ))
        } else {
            self.reader.seek(SeekFrom::Start(self.offset)).await?;
            Ok(None)
        }
    }

    pub(crate) async fn check_rotation(&mut self) -> bool {
        let meta = match tokio::fs::metadata(&self.path).await {
            Ok(m) => m,
            Err(_) => return false,
        };
        let cur_inode = meta.ino();
        let file_size = meta.len();
        if cur_inode != self.inode {
            info!(
                "Rotation detected (inode {} → {}), reopening from start",
                self.inode, cur_inode
            );
        } else if file_size < self.offset {
            info!(
                "Truncation detected (offset {} > size {}), reopening from start",
                self.offset, file_size
            );
        } else {
            return false;
        }
        match FileTailer::open(&self.path, 0).await {
            Ok(fresh) => {
                *self = fresh;
                true
            }
            Err(e) => {
                warn!("Reopen after rotation: {e:#}");
                false
            }
        }
    }
}

// ─── Bounded-channel reader task ─────────────────────────────────────────────

pub(crate) async fn reader_task(
    path: PathBuf,
    initial: TailState,
    tx: mpsc::Sender<(u64, String)>,
) {
    let mut tailer = loop {
        match FileTailer::open(&path, initial.offset).await {
            Ok(t) => break t,
            Err(e) => {
                warn!("Cannot open {}: {e:#}. Retrying in 5s…", path.display());
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    if initial.inode != 0 && tailer.inode != initial.inode {
        info!(
            "Rotation while stopped (saved_inode={} current_inode={}) — \
               starting from offset 0 on new file",
            initial.inode, tailer.inode
        );
        tailer = match FileTailer::open(&path, 0).await {
            Ok(t) => t,
            Err(e) => {
                error!("Reopen after startup rotation: {e:#}");
                return;
            }
        };
    }
    info!(
        "Tailing {} from offset={} (inode={})",
        path.display(),
        tailer.offset,
        tailer.inode
    );
    loop {
        match tailer.next_line().await {
            Ok(Some(line)) if !line.trim().is_empty() => {
                let offset = tailer.offset;
                trace!(offset, len = line.len(), "read line");
                if tx.send((offset, line)).await.is_err() {
                    debug!("reader: channel closed — shutting down");
                    return;
                }
            }
            Ok(Some(_)) => {
                trace!("reader: blank line skipped");
            }
            Ok(None) => {
                if tailer.check_rotation().await {
                    debug!(
                        inode = tailer.inode,
                        "reader: rotation handled — reopened from offset 0"
                    );
                } else {
                    trace!("reader: EOF — waiting for new data");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                error!("reader: I/O error on {}: {e:#}", path.display());
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
