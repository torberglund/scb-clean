# SCB API pipeline

Operational bundle for running the SCB data collection pipeline and related batch utilities.

## Layout
- `main.py` / `main.conf` - entry point and configuration for the arbetsstallen -> foretag -> join pipeline.
- `code/` - shared modules (arbetsstallen fetcher, foretag fetcher with CSV cache, joiner, logging helpers).
- `cache/foretag_cache.csv` - persistent foretag cache (auto-created).
- `output/` - pipeline artefacts (`arbetsstallen/`, `foretag/`, `join/`).
- `logs/` - log files for each stage plus the pipeline driver.
- `cert-pw/` - client certificate bundle and password used by the API calls.

## Running the pipeline
1. Adjust `main.conf` to match the desired SNI codes, arbetsstallen branch depth, zip range, and cache TTL.
2. Ensure `cert-pw/` contains the active SCB certificate bundle and password file.
3. Execute the pipeline from the project root (`scb-api-pipeline/`):

   ```bash
   python main.py            # Uses main.conf in the folder
   python main.py alt.conf   # Optional explicit config path (relative or absolute)
   ```

The foretag stage reuses entries in `cache/foretag_cache.csv` when they are newer than the configured `foretag_cache_max_age`.
Fresh API responses overwrite stale rows and extend the cache automatically.
