//! Received state-sync index and inline data representation.

use entangle_core::{is_valid_sync_id, StateKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};
use tracing::warn;

/// A verified payload received from an entangled particle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxItem {
    /// Unique transfer identifier.
    pub sync_id: String,
    /// Sending particle identity.
    pub from_particle_id: String,
    /// Sending particle name.
    pub from_name: String,
    /// Payload format.
    pub kind: StateKind,
    /// Optional sender label.
    pub label: Option<String>,
    /// RFC 3339 receive time.
    pub received_at: String,
    /// Verified payload size.
    pub bytes: u64,
    /// Verified lowercase SHA-256.
    pub sha256: String,
    /// Inline JSON value for JSON payloads.
    pub state: Option<Value>,
    /// Path to a received file.
    pub path: Option<PathBuf>,
    /// Optional inline UTF-8 file body.
    pub text: Option<String>,
}

/// Atomically writes an inbox item's metadata beside its payload directory.
pub async fn persist(inbox_dir: &Path, item: &InboxItem) -> io::Result<()> {
    let metadata = inbox_dir.join(format!("{}.json", item.sync_id));
    let temporary = inbox_dir.join(format!("{}.json.tmp", item.sync_id));
    let contents = serde_json::to_vec(item)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    let result = async {
        tokio::fs::write(&temporary, contents).await?;
        tokio::fs::rename(&temporary, metadata).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(temporary).await;
    }
    result
}

/// Removes an inbox item's metadata without deleting its payload files.
pub async fn forget(inbox_dir: &Path, sync_id: &str) -> io::Result<()> {
    match tokio::fs::remove_file(inbox_dir.join(format!("{sync_id}.json"))).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Loads valid inbox metadata, ordered by receive time and then sync ID.
pub async fn load(inbox_dir: &Path) -> Vec<InboxItem> {
    let mut entries = match tokio::fs::read_dir(inbox_dir).await {
        Ok(entries) => entries,
        Err(error) => {
            warn!(
                path = %inbox_dir.display(),
                error = %error,
                "unable to read inbox directory"
            );
            return Vec::new();
        }
    };
    let mut items = Vec::new();

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(error) => {
                warn!(
                    path = %inbox_dir.display(),
                    error = %error,
                    "unable to read inbox directory entry"
                );
                break;
            }
        };
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        match entry.file_type().await {
            Ok(file_type) if file_type.is_file() => {}
            Ok(_) => continue,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "unable to inspect inbox metadata"
                );
                continue;
            }
        }
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            warn!(path = %path.display(), "ignoring inbox metadata with invalid filename");
            continue;
        };
        if !is_valid_sync_id(stem) {
            warn!(path = %path.display(), "ignoring inbox metadata with invalid sync ID");
            continue;
        }

        let contents = match tokio::fs::read(&path).await {
            Ok(contents) => contents,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "unable to read inbox metadata"
                );
                continue;
            }
        };
        let item: InboxItem = match serde_json::from_slice(&contents) {
            Ok(item) => item,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "ignoring malformed inbox metadata"
                );
                continue;
            }
        };
        if item.sync_id != stem {
            warn!(
                path = %path.display(),
                item_sync_id = %item.sync_id,
                "ignoring inbox metadata whose sync ID does not match its filename"
            );
            continue;
        }
        if item.kind == StateKind::File {
            let path_exists = match item.path.as_ref() {
                Some(file_path) => match tokio::fs::try_exists(file_path).await {
                    Ok(exists) => exists,
                    Err(error) => {
                        warn!(
                            path = %file_path.display(),
                            error = %error,
                            "unable to check received inbox file"
                        );
                        false
                    }
                },
                None => false,
            };
            if !path_exists {
                warn!(
                    sync_id = %item.sync_id,
                    "ignoring inbox file whose payload no longer exists"
                );
                continue;
            }
        }
        items.push(item);
    }

    items.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.sync_id.cmp(&right.sync_id))
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_item(sync_id: &str, received_at: &str) -> InboxItem {
        InboxItem {
            sync_id: sync_id.into(),
            from_particle_id: "sender-id".into(),
            from_name: "sender".into(),
            kind: StateKind::Json,
            label: Some("test message".into()),
            received_at: received_at.into(),
            bytes: 16,
            sha256: "a".repeat(64),
            state: Some(json!({ "message": "hello" })),
            path: None,
            text: None,
        }
    }

    #[tokio::test]
    async fn persist_loads_items_in_order_and_forget_removes_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let earlier = sample_item("00000000000000000000000000000001", "2026-05-01T00:00:00Z");
        let later = sample_item("00000000000000000000000000000002", "2026-05-02T00:00:00Z");

        persist(temp.path(), &later).await.unwrap();
        persist(temp.path(), &earlier).await.unwrap();

        let loaded = load(temp.path()).await;
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].sync_id, earlier.sync_id);
        assert_eq!(loaded[1].sync_id, later.sync_id);
        assert_eq!(loaded[0].from_particle_id, earlier.from_particle_id);
        assert_eq!(loaded[0].from_name, earlier.from_name);
        assert_eq!(loaded[0].kind, StateKind::Json);
        assert_eq!(loaded[0].label, earlier.label);
        assert_eq!(loaded[0].received_at, earlier.received_at);
        assert_eq!(loaded[0].bytes, earlier.bytes);
        assert_eq!(loaded[0].sha256, earlier.sha256);
        assert_eq!(loaded[0].state, earlier.state);
        assert_eq!(loaded[0].path, earlier.path);
        assert_eq!(loaded[0].text, earlier.text);

        forget(temp.path(), "00000000000000000000000000000001")
            .await
            .unwrap();
        assert_eq!(load(temp.path()).await.len(), 1);
        forget(temp.path(), "00000000000000000000000000000003")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn load_skips_invalid_metadata_and_missing_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let inbox_dir = temp.path();
        let malformed_id = "00000000000000000000000000000001";
        let mismatch_stem = "00000000000000000000000000000002";
        let mismatch_id = "00000000000000000000000000000003";
        let missing_file_id = "00000000000000000000000000000004";
        let temporary_id = "00000000000000000000000000000005";
        let legacy_payload_id = "00000000000000000000000000000006";

        tokio::fs::write(
            inbox_dir.join(format!("{malformed_id}.json")),
            b"{not valid JSON",
        )
        .await
        .unwrap();
        tokio::fs::write(
            inbox_dir.join("not-a-sync-id.json"),
            serde_json::to_vec(&sample_item(malformed_id, "2026-05-01T00:00:00Z")).unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(
            inbox_dir.join(format!("{mismatch_stem}.json")),
            serde_json::to_vec(&sample_item(mismatch_id, "2026-05-01T00:00:00Z")).unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(
            inbox_dir.join(format!("{temporary_id}.json.tmp")),
            serde_json::to_vec(&sample_item(temporary_id, "2026-05-01T00:00:00Z")).unwrap(),
        )
        .await
        .unwrap();

        let mut missing_file = sample_item(missing_file_id, "2026-05-01T00:00:00Z");
        missing_file.kind = StateKind::File;
        missing_file.path = Some(inbox_dir.join("deleted-payload.txt"));
        tokio::fs::write(
            inbox_dir.join(format!("{missing_file_id}.json")),
            serde_json::to_vec(&missing_file).unwrap(),
        )
        .await
        .unwrap();

        let legacy_payload_dir = inbox_dir.join(legacy_payload_id);
        tokio::fs::create_dir(&legacy_payload_dir).await.unwrap();
        tokio::fs::write(
            legacy_payload_dir.join("entry.json"),
            serde_json::to_vec(&sample_item(legacy_payload_id, "2026-05-01T00:00:00Z")).unwrap(),
        )
        .await
        .unwrap();

        assert!(load(inbox_dir).await.is_empty());
    }
}
