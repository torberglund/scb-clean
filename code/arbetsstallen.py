import argparse
import configparser
import csv
import json
import logging
import os
import random
import re
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable, List, Sequence

import requests
from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat, pkcs12

try:
    from code.logging_utils import setup_logger
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from logging_utils import setup_logger


PFX_PATH = "cert-pw/Certifikat_SokPaVar_A00468_2025-09-26 10-10-47Z.pfx"
PFX_PASSWORD_PATH = "cert-pw/password.txt"
API_URL = "https://privateapi.scb.se/nv0101/v1/sokpavar/api/Ae/HamtaArbetsstallen"
RATE_LIMIT_DELAY = 1.5
ITERATION_THRESHOLD = 1950
ZIP_CHUNK_SIZES = (10_000, 1_000, 100, 10, 1)
BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_NAME = "main.conf"


logger = logging.getLogger("arbetsstallen")


def resolve_base_path(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        return BASE_DIR / path
    return path


def parse_config_str_list(raw: str) -> List[str]:
    if not raw:
        return []
    return [token for token in re.split(r"[\s,;]+", raw.strip()) if token]


def parse_config_int_list(raw: str) -> List[int]:
    return [int(token) for token in parse_config_str_list(raw)]


def load_config_defaults(config_path: Path) -> dict:
    config = configparser.ConfigParser()
    if not config.read(config_path, encoding="utf-8"):
        raise FileNotFoundError(f"Configuration file not found at {config_path}")
    if "pipeline" not in config:
        raise ValueError(f"Missing [pipeline] section in {config_path}")

    defaults: dict = {}
    pipeline_cfg = config["pipeline"]

    output_value = pipeline_cfg.get("arbetsstallen_output", fallback=None)
    if output_value:
        defaults["output_csv"] = resolve_base_path(output_value)

    target_codes = parse_config_str_list(pipeline_cfg.get("target_sni_codes", ""))
    if target_codes:
        defaults["target_sni_codes"] = target_codes

    bransch_levels = parse_config_int_list(pipeline_cfg.get("arbetsstallen_bransch_levels", ""))
    if bransch_levels:
        defaults["bransch_levels"] = bransch_levels

    start_value = pipeline_cfg.get("arbetsstallen_start_zip", fallback=None)
    if start_value:
        defaults["start_zip"] = int(start_value)

    end_value = pipeline_cfg.get("arbetsstallen_end_zip", fallback=None)
    if end_value:
        defaults["end_zip"] = int(end_value)

    try:
        verbose_value = pipeline_cfg.getboolean("verbose", fallback=None)
    except ValueError as exc:
        raise ValueError(f"Invalid boolean for verbose in {config_path}: {pipeline_cfg.get('verbose')}") from exc
    if verbose_value is not None:
        defaults["verbose"] = verbose_value

    if config.has_section("logging"):
        logging_cfg = config["logging"]
        log_value = logging_cfg.get("arbetsstallen_log", fallback=None)
        if log_value:
            defaults["log_path"] = resolve_base_path(log_value)

    avdelning_value = pipeline_cfg.get("arbetsstallen_avdelning", fallback=None)
    if avdelning_value:
        defaults["avdelning_code"] = avdelning_value.strip().upper()

    sni_csv_value = pipeline_cfg.get("arbetsstallen_sni_csv", fallback=None)
    if sni_csv_value:
        defaults["sni_csv_path"] = resolve_base_path(sni_csv_value)

    return defaults


def build_sni_prefix_map(csv_path: Path, avdelning_code: str | None = None) -> dict[str, List[str]]:
    prefix_map: dict[str, List[str]] = defaultdict(list)

    with csv_path.open(encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        for row in reader:
            if avdelning_code:
                ensiffrig = row.get("Ensiffrig SNI", "").strip()
                if not ensiffrig or not ensiffrig.startswith(avdelning_code):
                    continue

            femsiffrig = parse_sni_code(row.get("Femsiffrig SNI"))
            if len(femsiffrig) != 5:
                continue

            for length in range(1, len(femsiffrig) + 1):
                prefix = femsiffrig[:length]
                bucket = prefix_map[prefix]
                if femsiffrig not in bucket:
                    bucket.append(femsiffrig)

    return dict(prefix_map)


def parse_sni_code(raw_value: str) -> str:
    if not raw_value:
        return ""
    token = raw_value.strip().split()[0]
    return token.replace(".", "").strip()


def normalise_sni_codes(codes: Sequence[str]) -> List[str]:
    numeric_codes = []
    for code in codes:
        if not isinstance(code, str):
            continue
        token = code.replace(".", "").strip()
        if token:
            numeric_codes.append(token)
    # Preserve the incoming order while deduplicating.
    normalised = list(dict.fromkeys(numeric_codes))
    return normalised


def load_target_codes(
    target_codes: Sequence[str],
    csv_path: Path | None,
    avdelning_code: str | None,
) -> List[str]:
    numeric_targets = normalise_sni_codes(target_codes)
    if not numeric_targets:
        return []

    if csv_path is None:
        raise ValueError("SNI lookup path must be provided to resolve target codes.")
    if not csv_path.exists():
        raise FileNotFoundError(f"SNI lookup table not found at {csv_path}")

    prefix_map = build_sni_prefix_map(csv_path, avdelning_code)
    if not prefix_map:
        raise ValueError(f"No SNI definitions could be loaded from {csv_path}")

    expanded_codes: List[str] = []
    for code in numeric_targets:
        trimmed = code[:5]
        if len(code) >= 5:
            matches = prefix_map.get(trimmed, [])
            if matches:
                expanded_codes.extend(matches)
            else:
                raise ValueError(f"SNI code {code} is not recognised for avdelning {avdelning_code or 'ALL'} in {csv_path}")
            continue

        matches = prefix_map.get(code, [])
        if not matches:
            raise ValueError(f"SNI prefix {code} is not recognised for avdelning {avdelning_code or 'ALL'} in {csv_path}")
        expanded_codes.extend(matches)

    ordered_codes: List[str] = []
    seen: set[str] = set()
    for code in expanded_codes:
        if len(code) != 5:
            continue
        if code not in seen:
            ordered_codes.append(code)
            seen.add(code)

    return ordered_codes


def get_pfx_password() -> bytes:
    with open(PFX_PASSWORD_PATH, "r", encoding="utf-8") as handle:
        return handle.read().strip().encode()


def make_api_call(session: requests.Session, payload: dict, verbose: bool = False) -> List[dict] | None:
    retries = 3
    backoff_factor = 10
    for attempt in range(1, retries + 1):
        try:
            response = session.post(API_URL, json=payload)
            response.raise_for_status()
            if not response.text:
                return []
            return response.json()
        except requests.exceptions.HTTPError as exc:
            if exc.response.status_code == 429:
                if verbose:
                    logger.info("Rate limit exceeded. Waiting for %s seconds before retrying...", backoff_factor)
                time.sleep(backoff_factor)
                continue
            if verbose:
                logger.error("HTTP Error: %s", exc)
                logger.error("Response body: %s", exc.response.text)
            return None
        except (requests.exceptions.RequestException, json.JSONDecodeError) as exc:
            message = str(exc)
            if verbose:
                logger.error("Request or JSON Decode Exception: %s", message)
            if "Remote end closed connection without response" in message:
                wait_minutes = random.randint(3, 7)
                if verbose:
                    logger.info("Remote disconnection detected. Waiting %s minutes before retrying...", wait_minutes)
                time.sleep(wait_minutes * 60)
                continue
            return None

    if verbose:
        logger.warning("Max retries exceeded. Skipping this request.")
    return None


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


def build_payload(bransch_level: int, codes: Sequence[str], varde1: str, varde2: str, operator: str) -> dict:
    return {
        "Arbetsstallestatus": "1",
        "variabler": [
            {
                "Varde1": varde1,
                "Varde2": varde2,
                "Operator": operator,
                "Variabel": "Postnr",
            }
        ],
        "Kategorier": [
            {"Kategori": "Bransch", "Kod": list(codes), "Branschniva": bransch_level}
        ],
    }


def append_records(records: Iterable[dict], all_data: list, all_headers: set, seen_ids: set) -> None:
    for item in records:
        all_headers.update(item.keys())
        identifier = item.get("CFARNr") or item.get("OrgNr") or json.dumps(item, sort_keys=True)
        if identifier not in seen_ids:
            seen_ids.add(identifier)
            all_data.append(item)


def process_zip_range(
    session: requests.Session,
    level: int,
    batch_start: int,
    batch_end: int,
    chunk_index: int,
    ordered_codes: Sequence[str],
    verbose: bool,
    all_data: list,
    all_headers: set,
    seen_ids: set,
) -> None:
    operator = "ArLikaMed" if batch_start == batch_end else "Mellan"
    varde1 = f"{batch_start:05d}"
    varde2 = "" if operator == "ArLikaMed" else f"{batch_end:05d}"
    payload = build_payload(level, ordered_codes, varde1, varde2, operator)
    data = make_api_call(session, payload, verbose)
    time.sleep(RATE_LIMIT_DELAY)

    if data:
        if len(data) > ITERATION_THRESHOLD and chunk_index + 1 < len(ZIP_CHUNK_SIZES) and batch_start < batch_end:
            next_size = ZIP_CHUNK_SIZES[chunk_index + 1]
            if verbose:
                logger.info(
                    "Found %s records for %s-%s (level %s). Refining to %s-zip chunks.",
                    len(data),
                    varde1,
                    varde2 or varde1,
                    level,
                    next_size,
                )
            for sub_start in range(batch_start, batch_end + 1, next_size):
                sub_end = min(sub_start + next_size - 1, batch_end)
                process_zip_range(
                    session,
                    level,
                    sub_start,
                    sub_end,
                    chunk_index + 1,
                    ordered_codes,
                    verbose,
                    all_data,
                    all_headers,
                    seen_ids,
                )
        else:
            if verbose:
                logger.info(
                    "Found %s records for %s-%s (level %s).",
                    len(data),
                    varde1,
                    varde2 or varde1,
                    level,
                )
            append_records(data, all_data, all_headers, seen_ids)
    elif data is None and verbose:
        logger.warning(
            "An error occurred for zip range %s-%s (bransch level %s).",
            varde1,
            varde2 or varde1,
            level,
        )


def main(
    output_csv: str,
    verbose: bool = True,
    start_zip: int = 0,
    end_zip: int = 99999,
    target_sni_codes: Sequence[str] | None = None,
    bransch_levels: Sequence[int] | None = None,
    log_path: Path | None = None,
    avdelning_code: str | None = None,
    sni_csv_path: Path | None = None,
):
    if log_path is None:
        log_path = Path(__file__).resolve().parents[1] / "logs" / "arbetsstallen" / "arbetsstallen.log"
    log_path = Path(log_path)
    setup_logger("arbetsstallen", log_path, verbose)

    if not target_sni_codes:
        raise ValueError("At least one SNI code must be provided to query arbetsställen.")
    target_codes = target_sni_codes

    if not bransch_levels:
        raise ValueError("At least one bransch level must be provided to query arbetsställen.")
    levels = tuple(bransch_levels)
    if any(level not in {1, 2, 3} for level in levels):
        raise ValueError("Bransch levels must be within 1-3.")

    logger.info("Starting data retrieval for zip codes %s-%s...", f"{start_zip:05d}", f"{end_zip:05d}")

    pfx_password = get_pfx_password()
    session, cert_path, key_path = create_requests_session(PFX_PATH, pfx_password)

    all_data = []
    all_headers: set = set()
    seen_ids: set = set()

    avdelning_token = avdelning_code.strip().upper() if avdelning_code else None
    sni_lookup_path = Path(sni_csv_path) if sni_csv_path is not None else None

    try:
        try:
            ordered_codes = load_target_codes(target_codes, sni_lookup_path, avdelning_token)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Unable to resolve SNI codes: %s", exc)
            return

        if not ordered_codes:
            logger.warning("No SNI codes resolved for avdelning %s.", avdelning_token or "ALL")
            return
        logger.info(
            "Resolved %s SNI codes for avdelning %s.",
            len(ordered_codes),
            avdelning_token or "ALL",
        )

        top_chunk = ZIP_CHUNK_SIZES[0]
        for chunk_start in range(start_zip, end_zip + 1, top_chunk):
            chunk_end = min(chunk_start + top_chunk - 1, end_zip)
            if verbose:
                logger.info(
                    "Processing zip code range: %s-%s",
                    f"{chunk_start:05d}",
                    f"{chunk_end:05d}",
                )

            for level in levels:
                formatted_codes = [f"{code[:2]}.{code[2:]}" if len(code) == 5 else code for code in ordered_codes]
                if verbose:
                    logger.info(
                        "Querying bransch level %s with codes: %s",
                        level,
                        ", ".join(formatted_codes),
                    )

                process_zip_range(
                    session,
                    level,
                    chunk_start,
                    chunk_end,
                    0,
                    ordered_codes,
                    verbose,
                    all_data,
                    all_headers,
                    seen_ids,
                )

        path = Path(output_csv)
        path.parent.mkdir(parents=True, exist_ok=True)

        if all_data:
            logger.info("Writing %s records to %s...", len(all_data), path)
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=sorted(all_headers))
                writer.writeheader()
                writer.writerows(all_data)
            logger.info("Data retrieval complete.")
        else:
            logger.info("No data retrieved.")

        if verbose:
            logger.info("Summary:")
            logger.info("  - Processed zip codes from %s to %s.", f"{start_zip:05d}", f"{end_zip:05d}")
            logger.info("  - Found a total of %s records.", len(all_data))

    finally:
        for artifact in (cert_path, key_path):
            try:
                os.remove(artifact)
            except FileNotFoundError:
                logger.debug("Temporary credential file already removed: %s", artifact)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Retrieve workplace data from the SCB API by iterating through zip codes.",
    )
    parser.add_argument("--conf", default=DEFAULT_CONFIG_NAME, help="Path to the configuration file (defaults to main.conf).")
    parser.add_argument("output_csv", nargs="?", help="Path to the output CSV file.")
    parser.add_argument("--start", type=int, default=None, help="The starting zip code (overrides configuration).")
    parser.add_argument("--end", type=int, default=None, help="The ending zip code (overrides configuration).")
    parser.add_argument("--sni-codes", nargs="*", default=None, help="SNI codes to include (overrides configuration).")
    parser.add_argument(
        "--bransch-levels",
        nargs="*",
        type=int,
        default=None,
        help="Bransch levels (1-3) to query (overrides configuration).",
    )
    parser.add_argument("--quiet", action="store_true", help="Disable verbose output (overrides configuration).")
    parser.add_argument(
        "--log-path",
        default=None,
        help="Path to the log file (overrides configuration).",
    )
    parser.add_argument(
        "--avdelning",
        default=None,
        help="Avdelning code to filter SNI definitions (overrides configuration).",
    )
    parser.add_argument(
        "--sni-csv",
        default=None,
        help="Path to the SNI lookup CSV file (overrides configuration).",
    )
    args = parser.parse_args()

    config_defaults: dict = {}
    config_path: Path | None = None
    if args.conf:
        config_path = resolve_base_path(args.conf)
        if config_path.exists():
            try:
                config_defaults = load_config_defaults(config_path)
            except (FileNotFoundError, ValueError, configparser.Error) as exc:
                parser.error(f"Failed to load configuration {config_path}: {exc}")
        elif args.conf != DEFAULT_CONFIG_NAME:
            parser.error(f"Configuration file not found at {config_path}")

    output_csv_value = args.output_csv or config_defaults.get("output_csv")
    if output_csv_value is None:
        parser.error("Output CSV path must be provided either as an argument or in the configuration.")

    start_zip = args.start if args.start is not None else config_defaults.get("start_zip", 0)
    end_zip = args.end if args.end is not None else config_defaults.get("end_zip", 99999)

    if args.sni_codes is not None:
        target_codes = args.sni_codes
    else:
        target_codes = config_defaults.get("target_sni_codes")
    if not target_codes:
        parser.error("At least one SNI code must be provided via --sni-codes or the configuration.")

    if args.bransch_levels is not None:
        bransch_levels = args.bransch_levels
    else:
        bransch_levels = config_defaults.get("bransch_levels")
    if not bransch_levels:
        parser.error("At least one bransch level must be provided via --bransch-levels or the configuration.")

    verbose_flag = config_defaults.get("verbose", True)
    if args.quiet:
        verbose_flag = False

    log_path_value = args.log_path or config_defaults.get("log_path")
    if isinstance(log_path_value, str) and log_path_value:
        log_path = resolve_base_path(log_path_value)
    else:
        log_path = log_path_value

    avdelning_value = args.avdelning or config_defaults.get("avdelning_code")
    sni_csv_value = args.sni_csv or config_defaults.get("sni_csv_path")
    if isinstance(sni_csv_value, str) and sni_csv_value:
        sni_csv_value = resolve_base_path(sni_csv_value)
    if sni_csv_value is None:
        sni_csv_value = BASE_DIR / "sni.csv"

    main(
        str(output_csv_value),
        verbose=verbose_flag,
        start_zip=start_zip,
        end_zip=end_zip,
        target_sni_codes=target_codes,
        bransch_levels=bransch_levels,
        log_path=log_path,
        avdelning_code=avdelning_value,
        sni_csv_path=sni_csv_value,
    )
