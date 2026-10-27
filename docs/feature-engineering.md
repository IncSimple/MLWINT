# Feature engineering
EMBER feature version 2 has 2,381 columns. The predictor converts arrays to
float32, accepts 1D/2D input, and rejects incorrect widths and nonfinite values.
Negative signed hashing values are valid and must not be clipped.

| Feature group | Inclusive indices |
|---|---|
| Byte histogram | 0–255 |
| Byte entropy | 256–511 |
| Strings | 512–615 |
| General | 616–625 |
| Header | 626–687 |
| Section | 688–942 |
| Imports | 943–2222 |
| Exports | 2223–2350 |
| Data directories | 2351–2380 |

The schema follows the inspected upstream EMBER v2 layout and project mapping
script. `vectorize_ember_chunks.py` uses precomputed feature dictionaries, not a
new raw-byte parser. The handoff reports LIEF incompatibility on a different
extraction path; raw executable extraction is outside the tested service interface.
