# Data
Raw and generated data stay local. See [acquisition and checksum](../docs/dataset.md).
Expected local paths: `raw/ember2018/*.jsonl`,
`processed/ember/train_full_chunks/{X_*,y_*}.npy`, and
`processed/ember/model_data/{X_sample,y_sample}.npy`.
The original manifest reports 600,000 labeled records across 1,203 chunks.
Keep model sample arrays aligned with the saved split. Regeneration commands
are documented in the README; do not rerun them over working artifacts.
