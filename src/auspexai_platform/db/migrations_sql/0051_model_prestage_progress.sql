-- 0051_model_prestage_progress.sql — D12 Inc 5c download progress.
--
-- The worker reports in-flight model-pull progress in its heartbeat
-- ({model_id: {bytes_downloaded, total_bytes}}); the coordinator records the
-- latest sample on the open prestage row so a queued researcher sees the
-- download advance as a % instead of a binary "downloading". Best-effort and
-- transient: download_total_bytes may stay NULL (HF metadata unavailable) → the
-- UI shows bytes-only, no %.
ALTER TABLE model_prestage ADD COLUMN download_bytes INTEGER;
ALTER TABLE model_prestage ADD COLUMN download_total_bytes INTEGER;
