"""
Utility script to retrieve `Bransch 1P` codes per organisation number.

The script reads organisation numbers from `input.csv.enc`, decrypting it
with the password stored in `pw.txt`. Each organisation number is assigned
a sequential ID (1, 2, 3, …) based on its position in the decrypted input.
The SCB arbetsställen API is queried per organisation number, and the
resulting `Bransch_1P, kod` is appended to `output.csv` together with the
corresponding ID. Results are flushed to disk after each row so an
interrupted run can resume without reprocessing completed entries.
"""

import argparse
import csv
import io
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import requests
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat, pkcs12


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

DEFAULT_INPUT_PATH = BASE_DIR / "input.csv.enc"
DEFAULT_PASSWORD_PATH = BASE_DIR / "pw.txt"
DEFAULT_OUTPUT_PATH = BASE_DIR / "output.csv"
PFX_PATH = PROJECT_ROOT / "cert-pw" / "Certifikat_SokPaVar_A00468_2025-09-26 10-10-47Z.pfx"
PFX_PASSWORD_PATH = PROJECT_ROOT / "cert-pw" / "password.txt"

API_URL = "https://privateapi.scb.se/nv0101/v1/sokpavar/api/Ae/HamtaArbetsstallen"
RATE_LIMIT_DELAY = 1.5  # seconds between calls to stay well within the quota.
MAX_ATTEMPTS = 3
RATE_LIMIT_BACKOFF = 10  # seconds to wait after a 429 response.
REMOTE_DISCONNECT_RANGE = (3 * 60, 7 * 60)  # wait 3-7 minutes on remote disconnect.
PBKDF2_ITERATIONS = 10000
PBKDF2_KEY_LENGTH = 48  # 32 bytes key + 16 bytes IV.
OPENSSL_SALT_HEADER = b"Salted__"


class CertificateSession:
    """Context manager that prepares the client certificate and cleans up temp files."""

    def __init__(self, pfx_path: Path, password: bytes) -> None:
        self._pfx_path = pfx_path
        self._password = password
        self._session = None
        self._temp_paths: List[Path] = []

    def __enter__(self) -> requests.Session:
        with self._pfx_path.open("rb") as handle:
            pfx_data = handle.read()

        private_key, certificate, _ = pkcs12.load_key_and_certificates(pfx_data, self._password)
        if not private_key or not certificate:
            raise RuntimeError("Unable to load PFX certificate bundle.")

        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        cert_file.write(certificate.public_bytes(encoding=pkcs12.serialization.Encoding.PEM))
        cert_file.close()

        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        key_file.write(
            private_key.private_bytes(
                encoding=pkcs12.serialization.Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
        key_file.close()

        self._temp_paths = [Path(cert_file.name), Path(key_file.name)]

        self._session = requests.Session()
        self._session.cert = (cert_file.name, key_file.name)
        return self._session

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._session is not None:
            self._session.close()

        for path in self._temp_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def read_pfx_password(path: Path) -> bytes:
    return path.read_text(encoding="utf-8").strip().encode("utf-8")


def read_password(path: Path) -> bytes:
    return path.read_text(encoding="utf-8").strip().encode("utf-8")


def decrypt_openssl_aes256cbc(data: bytes, password: bytes) -> bytes:
    if not data.startswith(OPENSSL_SALT_HEADER) or len(data) < 16:
        raise ValueError("Encrypted input does not contain an OpenSSL salt header.")

    salt = data[8:16]
    ciphertext = data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key_material = kdf.derive(password)
    key = key_material[:32]
    iv = key_material[32:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def load_org_numbers_from_text(text: str) -> List[str]:
    org_numbers: List[str] = []
    warned_non_numeric = False
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        value = row[0].strip()
        if not value:
            continue
        if not value.isdigit():
            if not warned_non_numeric:
                print(
                    f"Skipping non-numeric value in input (showing once): {value}",
                    file=sys.stderr,
                )
                warned_non_numeric = True
            continue
        org_numbers.append(value)
    return org_numbers


def load_processed(path: Path) -> Dict[str, str]:
    processed: Dict[str, str] = {}
    if not path.exists():
        return processed

    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header is None:
            return processed
        if header[0] != "id":
            raise RuntimeError(
                f"Unexpected header in output file: {header!r}. Expected first column to be 'id'."
            )
        for row in reader:
            if not row:
                continue
            identifier = row[0].strip()
            kod = row[1].strip() if len(row) > 1 else ""
            if identifier:
                processed[identifier] = kod
    return processed


def ensure_output_header(path: Path) -> None:
    if path.exists() and path.stat().st_size > 0:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "kod"])


def extract_bransch_code(records: Sequence[dict], verbose: bool = False) -> str:
    codes = []
    for item in records:
        code = item.get("Bransch_1P, kod") or item.get("Bransch_1, kod")
        if code:
            codes.append(code.strip())

    if not codes:
        return ""

    unique_codes = list(dict.fromkeys(code for code in codes if code))
    if verbose and len(unique_codes) > 1:
        print(
            f"  > Multiple `Bransch 1P` codes found for org; using first: {', '.join(unique_codes)}",
            file=sys.stderr,
        )
    return unique_codes[0]


def make_payload(orgnr: str) -> dict:
    return {
        "variabler": [
            {
                "Varde1": orgnr,
                "Varde2": "",
                "Operator": "ArLikaMed",
                "Variabel": "OrgNr (10 siffror)",
            }
        ]
    }


def fetch_bransch_code(session: requests.Session, orgnr: str, verbose: bool = False) -> Optional[str]:
    last_error: Optional[str] = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = session.post(API_URL, json=make_payload(orgnr), timeout=30)
            response.raise_for_status()
            if not response.text:
                if verbose:
                    print(f"  > Empty response for {orgnr}.", file=sys.stderr)
                return ""

            try:
                records = response.json()
            except json.JSONDecodeError as exc:
                last_error = f"Invalid JSON: {exc}"
                if verbose:
                    print(f"  > Failed to parse response for {orgnr}: {exc}", file=sys.stderr)
                continue

            if not isinstance(records, list):
                if verbose:
                    print(f"  > Unexpected payload for {orgnr}: {records!r}", file=sys.stderr)
                last_error = "Unexpected payload structure"
                continue

            if not records:
                if verbose:
                    print(f"  > No records found for {orgnr}.", file=sys.stderr)
                return ""

            return extract_bransch_code(records, verbose=verbose)

        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response else "?"
            if status == 429:
                if verbose:
                    print(
                        f"  > Rate limit hit for {orgnr}; backing off {RATE_LIMIT_BACKOFF}s (attempt {attempt}/{MAX_ATTEMPTS}).",
                        file=sys.stderr,
                    )
                time.sleep(RATE_LIMIT_BACKOFF)
                last_error = f"429 rate limit (attempt {attempt})"
                continue

            last_error = f"HTTP {status}: {exc}"
            if verbose:
                body = exc.response.text if exc.response is not None else "<no body>"
                print(
                    f"  > HTTP error for {orgnr} (attempt {attempt}/{MAX_ATTEMPTS}): {exc}\n      Body: {body[:200]}",
                    file=sys.stderr,
                )
            time.sleep(RATE_LIMIT_DELAY)
        except requests.exceptions.RequestException as exc:
            message = str(exc)
            if "Remote end closed connection without response" in message:
                wait_seconds = random.randint(*REMOTE_DISCONNECT_RANGE)
                if verbose:
                    print(
                        f"  > Remote disconnect for {orgnr}; waiting {wait_seconds // 60} min before retry (attempt {attempt}/{MAX_ATTEMPTS}).",
                        file=sys.stderr,
                    )
                time.sleep(wait_seconds)
                last_error = "Remote disconnect"
                continue

            if verbose:
                print(
                    f"  > Request exception for {orgnr} (attempt {attempt}/{MAX_ATTEMPTS}): {exc}",
                    file=sys.stderr,
                )
            last_error = f"Request exception: {exc}"
            time.sleep(RATE_LIMIT_DELAY)
        finally:
            time.sleep(RATE_LIMIT_DELAY)

    if verbose and last_error:
        print(f"  > Giving up on {orgnr}: {last_error}", file=sys.stderr)
    return None


def main(input_path: Path, output_path: Path, password_path: Path, verbose: bool = False) -> None:
    if not input_path.exists():
        print(f"Encrypted input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if not password_path.exists():
        print(f"Password file not found: {password_path}", file=sys.stderr)
        sys.exit(1)

    try:
        password = read_password(password_path)
    except OSError as exc:
        print(f"Failed to read password file: {exc}", file=sys.stderr)
        sys.exit(1)

    if not password:
        print("Password file is empty.", file=sys.stderr)
        sys.exit(1)

    try:
        encrypted_data = input_path.read_bytes()
    except OSError as exc:
        print(f"Failed to read encrypted input: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        decrypted_bytes = decrypt_openssl_aes256cbc(encrypted_data, password)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to decrypt input: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        csv_text = decrypted_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        csv_text = decrypted_bytes.decode("utf-8")

    org_numbers = load_org_numbers_from_text(csv_text)

    if not org_numbers:
        print("No organisation numbers found in input.")
        return

    indexed_orgs = [(str(index), org) for index, org in enumerate(org_numbers, start=1)]

    processed = load_processed(output_path)
    remaining = [(org_id, org) for org_id, org in indexed_orgs if org_id not in processed]

    if not remaining:
        print("All organisation numbers already processed.")
        return

    ensure_output_header(output_path)

    password = read_pfx_password(PFX_PASSWORD_PATH)

    with CertificateSession(PFX_PATH, password) as session, output_path.open(
        "a", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)

        for index, (org_id, orgnr) in enumerate(remaining, start=1):
            if verbose:
                print(f"[{index}/{len(remaining)}] Processing {orgnr} (id={org_id})...")

            result = fetch_bransch_code(session, orgnr, verbose=verbose)
            if result is None:
                # Persist blank code to mark as processed but highlight failure.
                if verbose:
                    print(
                        f"  > Failed to retrieve Bransch 1P code for {orgnr} (id={org_id}).",
                        file=sys.stderr,
                    )
                writer.writerow([org_id, ""])
            else:
                writer.writerow([org_id, result])

            handle.flush()
            os.fsync(handle.fileno())

    print(f"Processed {len(remaining)} organisation numbers. Results appended to {output_path}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Retrieve Bransch 1P codes for organisation numbers from an encrypted input CSV."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Path to input CSV (default: {DEFAULT_INPUT_PATH})",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        default=DEFAULT_PASSWORD_PATH,
        help=f"Path to password file used for decrypting the input (default: {DEFAULT_PASSWORD_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Path to output CSV (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    args = parser.parse_args()
    main(args.input, args.output, args.password_file, verbose=args.verbose)
