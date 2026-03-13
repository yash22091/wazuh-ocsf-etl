use std::path::PathBuf;

// ─── State persistence ────────────────────────────────────────────────────────
//
// The state file stores the inode + byte offset of the last successfully
// flushed batch.  On restart the reader seeks directly to that position.

#[derive(Debug, Default, Clone)]
pub(crate) struct TailState {
    /// Linux inode of the tailed file when this state was saved.
    pub(crate) inode:  u64,
    /// Byte offset immediately after the last FLUSHED line.
    pub(crate) offset: u64,
}

pub(crate) struct StateStore { pub(crate) path: PathBuf }

impl StateStore {
    pub(crate) fn new(path: PathBuf) -> Self { Self { path } }

    /// Load saved state.  Returns default (offset=0, inode=0) when absent.
    pub(crate) fn load(&self) -> TailState {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t)  => t,
            Err(_) => return TailState::default(),
        };
        let mut s = TailState::default();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("inode=")  { s.inode  = v.trim().parse().unwrap_or(0); }
            if let Some(v) = line.strip_prefix("offset=") { s.offset = v.trim().parse().unwrap_or(0); }
        }
        s
    }

    /// Atomically persist state: write to .tmp then rename (crash-safe).
    pub(crate) fn save(&self, s: &TailState) -> std::io::Result<()> {
        if let Some(p) = self.path.parent() { std::fs::create_dir_all(p)?; }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, format!("inode={}\noffset={}\n", s.inode, s.offset))?;
        std::fs::rename(&tmp, &self.path)
    }
}
