import argparse
import csv
import json
import logging
import os
import random
import tempfile
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import requests
from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat, pkcs12

try:
    from code.logging_utils import setup_logger
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from logging_utils import setup_logger


PFX_PATH = "cert-pw/Certifikat_SokPaVar_A00468_2025-09-26 10-10-47Z.pfx"
PFX_PASSWORD_PATH = "cert-pw/password.txt"
API_URL = "https://privateapi.scb.se/nv0101/v1/sokpavar/api/Je/HamtaForetag"
RATE_LIMIT_DELAY = 1.5
MAX_ORG_ATTEMPTS = 3
ORG_PAUSE_THRESHOLD = 10_000
ORG_PAUSE_DURATION = 60 * 60
DEFAULT_CACHE_MAX_AGE_DAYS = 30


logger = logging.getLogger("foretag")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_pfx_password() -> bytes:
    with open(PFX_PASSWORD_PATH, "r", encoding="utf-8") as handle:
        return handle.read().strip().encode()


def make_api_call(session: requests.Session, payload: dict, verbose: bool = False, retries: int = 3):
    backoff_factor = 10
    last_error_info = None

    for _ in range(retries):
        try:
            response = session.post(API_URL, json=payload)
            response.raise_for_status()
            if not response.text:
                return [], None
            return response.json(), None
        except requests.exceptions.HTTPError as exc:
            if exc.response.status_code == 429:
                if verbose:
                    logger.info("Rate limit exceeded. Waiting for %s seconds before retrying...", backoff_factor)
                time.sleep(backoff_factor)
                continue
            if verbose:
                logger.error("HTTP Error: %s", exc)
                logger.error("Response body: %s", exc.response.text)
            return None, {"type": "http_error", "message": str(exc)}
        except (requests.exceptions.RequestException, json.JSONDecodeError) as exc:
            error_message = str(exc)
            if verbose:
                logger.error("Request or JSON Decode Exception: %s", error_message)

            if "Remote end closed connection without response" in error_message:
                wait_minutes = random.randint(3, 7)
                if verbose:
                    logger.info("Remote disconnection detected. Waiting %s minutes before retrying...", wait_minutes)
                time.sleep(wait_minutes * 60)
                last_error_info = {
                    "type": "remote_disconnected",
                    "message": "Remote end closed connection without response",
                }
                continue

            last_error_info = {"type": "request_exception", "message": error_message}
            return None, last_error_info

    if verbose:
        logger.warning("Max retries exceeded. Skipping this request.")
    return None, last_error_info or {"type": "unknown_error", "message": "Max retries exceeded"}


def create_requests_session(pfx_path: str, pfx_password: bytes):
    with open(pfx_path, "rb") as handle:
        pfx_data = handle.read()

    private_key, certificate, _ = pkcs12.load_key_and_certificates(pfx_data, pfx_password)

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(certificate.public_bytes(encoding=pkcs12.serialization.Encoding.PEM))
    cert_file.close()

    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(private_key.private_bytes(
        encoding=pkcs12.serialization.Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ))
    key_file.close()

    session = requests.Session()
    session.cert = (cert_file.name, key_file.name)
    return session, cert_file.name, key_file.name


def load_cache(cache_path: Path) -> Dict[str, dict]:
    """Load cached företag rows from a CSV file grouped by organisation number."""
    cache: Dict[str, dict] = {}
    if not cache_path.exists() or cache_path.stat().st_size == 0:
        return cache

    try:
        with cache_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                return cache
            for row in reader:
                org_nr = (row.get("OrgNr") or "").strip()
                if not org_nr:
                    continue
                record = dict(row)
                record["OrgNr"] = org_nr
                retrieved_at = (record.get("RetrievedAt") or "").strip()
                if retrieved_at:
                    record["RetrievedAt"] = retrieved_at

                entry = cache.setdefault(org_nr, {"retrieved_at": retrieved_at, "rows": []})
                if retrieved_at:
                    entry["retrieved_at"] = retrieved_at
                entry["rows"].append(record)
    except OSError as exc:
        logger.warning("Failed to read cache %s (%s). Starting with an empty cache.", cache_path, exc)

    return cache


def save_cache(cache_path: Path, cache: Dict[str, dict]) -> None:
    """Persist the cache mapping to CSV."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    rows: List[dict] = []
    headers: set = set()
    for entry in cache.values():
        for row in entry.get("rows", []):
            row_copy = dict(row)
            rows.append(row_copy)
            headers.update(row_copy.keys())

    if not rows:
        cache_path.write_text("", encoding="utf-8")
        return

    preferred_order = [key for key in ("OrgNr", "RetrievedAt") if key in headers]
    remaining_headers = sorted(headers - set(preferred_order))
    fieldnames = preferred_order + remaining_headers

    with cache_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def is_cache_entry_stale(entry: dict, max_age_days: int) -> bool:
    retrieved_at = entry.get("retrieved_at")
    if not retrieved_at:
        rows = entry.get("rows") or []
        if rows:
            retrieved_at = rows[0].get("RetrievedAt")
    if not retrieved_at:
        return True
    try:
        ts = datetime.fromisoformat(str(retrieved_at).replace("Z", "+00:00"))
    except ValueError:
        return True
    age = datetime.now(timezone.utc) - ts
    return age.days > max_age_days


def prepare_records(records: Iterable[dict], retrieved_at: str, org_nr: str | None = None) -> List[dict]:
    prepared = []
    for item in records:
        entry = deepcopy(item)
        if org_nr and not entry.get("OrgNr"):
            entry["OrgNr"] = org_nr
        entry["RetrievedAt"] = retrieved_at
        prepared.append(entry)
    if not prepared:
        fallback = {"RetrievedAt": retrieved_at}
        if org_nr:
            fallback["OrgNr"] = org_nr
        prepared.append(fallback)
    return prepared


def main(
    input_csv: str,
    output_csv: str,
    verbose: bool = True,
    cache_path: Path | None = None,
    cache_max_age_days: int = DEFAULT_CACHE_MAX_AGE_DAYS,
    log_path: Path | None = None,
):
    if log_path is None:
        log_path = Path(__file__).resolve().parents[1] / "logs" / "foretag" / "foretag.log"
    log_path = Path(log_path)
    setup_logger("foretag", log_path, verbose)

    if cache_path is None:
        cache_path = Path(__file__).resolve().parents[1] / "cache" / "foretag_cache.csv"
    cache_path = Path(cache_path)

    logger.info("Starting company data retrieval...")

    if not os.path.exists(input_csv):
        logger.error("Input file not found at %s", input_csv)
        return

    logger.info("Reading unique organization numbers from %s...", input_csv)
    org_nrs = set()
    with open(input_csv, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            org_nr = row.get("OrgNr")
            if org_nr:
                org_nrs.add(org_nr)

    unique_org_nrs = list(org_nrs)
    logger.info("Found %s unique organization numbers.", len(unique_org_nrs))

    if not unique_org_nrs:
        logger.info("No organization numbers found in the input file.")
        return

    pfx_password = get_pfx_password()
    session, cert_path, key_path = create_requests_session(PFX_PATH, pfx_password)

    cache = load_cache(cache_path)
    cache_updated = False

    all_company_data: List[dict] = []
    all_headers: set = set()

    try:
        for index, org_nr in enumerate(unique_org_nrs, start=1):
            if verbose:
                logger.info("Processing OrgNr %s/%s: %s", index, len(unique_org_nrs), org_nr)

            cache_entry = cache.get(org_nr)
            if cache_entry and not is_cache_entry_stale(cache_entry, cache_max_age_days):
                retrieved_at = cache_entry.get("retrieved_at", "")
                cached_rows = cache_entry.get("rows", [])
                if verbose:
                    logger.info(
                        "Reusing cached result retrieved at %s%s",
                        retrieved_at or "<unknown>",
                        f" ({len(cached_rows)} rows)" if cached_rows else "",
                    )

                if cached_rows:
                    row_copies = [dict(row) for row in cached_rows]
                    for record in row_copies:
                        all_headers.update(record.keys())
                    all_company_data.extend(row_copies)
                else:
                    prepared = prepare_records([], retrieved_at, org_nr)
                    for record in prepared:
                        all_headers.update(record.keys())
                    all_company_data.extend(prepared)
                continue

            payload = {
                "variabler": [
                    {
                        "Varde1": org_nr,
                        "Varde2": "",
                        "Operator": "ArLikaMed",
                        "Variabel": "OrgNr (10 siffror)",
                    }
                ]
            }

            error_info = None

            for attempt in range(1, MAX_ORG_ATTEMPTS + 1):
                company_data, error_info = make_api_call(session, payload, verbose, retries=1)

                if company_data is not None:
                    retrieved_at = utc_now_iso()
                    if verbose:
                        if company_data:
                            logger.info("Found %s records.", len(company_data))
                        else:
                            logger.info("No records found for this OrgNr.")

                    prepared = prepare_records(company_data, retrieved_at, org_nr)
                    cache[org_nr] = {
                        "retrieved_at": retrieved_at,
                        "rows": [dict(record) for record in prepared],
                    }
                    cache_updated = True

                    for record in prepared:
                        all_headers.update(record.keys())
                    all_company_data.extend(prepared)
                    time.sleep(RATE_LIMIT_DELAY)
                    break

                if error_info and error_info.get("type") == "remote_disconnected":
                    if attempt < MAX_ORG_ATTEMPTS:
                        logger.warning(
                            "Remote disconnection persists (attempt %s/%s). Retrying OrgNr %s...",
                            attempt,
                            MAX_ORG_ATTEMPTS,
                            org_nr,
                        )
                        time.sleep(RATE_LIMIT_DELAY)
                        continue

                    error_message = error_info.get("message", "Remote disconnection")
                    logger.error(
                        "Remote disconnection after %s attempts. Logging failure for OrgNr %s.",
                        MAX_ORG_ATTEMPTS,
                        org_nr,
                    )
                    failure_timestamp = utc_now_iso()
                    failure_record = {
                        "OrgNr": org_nr,
                        "Error": f"Remote disconnection after {MAX_ORG_ATTEMPTS} attempts: {error_message}",
                        "RetrievedAt": failure_timestamp,
                    }
                    all_headers.update(failure_record.keys())
                    all_company_data.append(failure_record)
                    break

                if verbose:
                    logger.info("No records found for this OrgNr.")
                time.sleep(RATE_LIMIT_DELAY)
                break

            processed_count = index
            if processed_count % ORG_PAUSE_THRESHOLD == 0 and processed_count < len(unique_org_nrs):
                logger.info(
                    "Reached %s processed OrgNr. Pausing for %s minutes to protect the API.",
                    processed_count,
                    ORG_PAUSE_DURATION // 60,
                )
                time.sleep(ORG_PAUSE_DURATION)

        output_path = Path(output_csv)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if all_company_data:
            logger.info("Writing %s company records to %s...", len(all_company_data), output_path)
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=sorted(all_headers))
                writer.writeheader()
                writer.writerows(all_company_data)
            logger.info("Company data retrieval complete.")
        else:
            logger.info("No company data retrieved.")

        if cache_updated:
            logger.info("Persisting cache to %s", cache_path)
            save_cache(cache_path, cache)

    finally:
        for artifact in (cert_path, key_path):
            try:
                os.remove(artifact)
            except FileNotFoundError:
                logger.debug("Temporary credential file already removed: %s", artifact)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrieve company data from the SCB API.")
    parser.add_argument("input_csv", help="Path to the CSV file containing workplace data.")
    parser.add_argument("output_csv", help="Path to the output CSV file for company data.")
    parser.add_argument(
        "--cache-path",
        default=str(Path(__file__).resolve().parents[1] / "cache" / "foretag_cache.csv"),
        help="Path to the cache CSV file.",
    )
    parser.add_argument(
        "--cache-max-age-days",
        type=int,
        default=DEFAULT_CACHE_MAX_AGE_DAYS,
        help="Maximum cache age in days before refetching (defaults to 30).",
    )
    parser.add_argument("--quiet", action="store_true", help="Disable verbose output.")
    parser.add_argument(
        "--log-path",
        default=str(Path(__file__).resolve().parents[1] / "logs" / "foretag" / "foretag.log"),
        help="Path to the log file.",
    )
    args = parser.parse_args()

    main(
        args.input_csv,
        args.output_csv,
        verbose=not args.quiet,
        cache_path=Path(args.cache_path),
        cache_max_age_days=args.cache_max_age_days,
        log_path=Path(args.log_path),
    )
