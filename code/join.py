import argparse
import csv
import logging
from pathlib import Path

import pandas as pd

try:
    from code.logging_utils import setup_logger
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from logging_utils import setup_logger


logger = logging.getLogger("join")


def main(
    arbetsstallen_csv: str,
    foretag_csv: str,
    output_csv: str,
    verbose: bool = True,
    log_path: Path | None = None,
):
    if log_path is None:
        log_path = Path(__file__).resolve().parents[1] / "logs" / "join" / "join.log"
    log_path = Path(log_path)
    setup_logger("join", log_path, verbose)

    logger.info("Starting the join process...")

    try:
        arbetsstallen_df = pd.read_csv(arbetsstallen_csv, dtype=str)
        foretag_df = pd.read_csv(foretag_csv, dtype=str)

        logger.info("Read %s records from %s", len(arbetsstallen_df), arbetsstallen_csv)
        logger.info("Read %s records from %s", len(foretag_df), foretag_csv)

        merged_df = pd.merge(
            arbetsstallen_df,
            foretag_df,
            on="OrgNr",
            how="left",
            suffixes=("", "_foretag"),
        )

        cols_to_drop = [col for col in merged_df.columns if col.endswith("_foretag")]
        merged_df.drop(columns=cols_to_drop, inplace=True)

        output_path = Path(output_csv)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Writing %s merged records to %s...", len(merged_df), output_path)
        merged_df.to_csv(output_path, index=False, quoting=csv.QUOTE_ALL)

        logger.info("Join process complete.")

    except FileNotFoundError as exc:
        logger.error("Missing input file: %s", exc)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("An error occurred during join: %s", exc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Join workplace and company data.")
    parser.add_argument("arbetsstallen_csv", help="Path to the workplace data CSV file (from arbetsstallen.py).")
    parser.add_argument("foretag_csv", help="Path to the company data CSV file (from foretag.py).")
    parser.add_argument("output_csv", help="Path to the final, merged output CSV file.")
    parser.add_argument("--quiet", action="store_true", help="Disable verbose output.")
    parser.add_argument(
        "--log-path",
        default=str(Path(__file__).resolve().parents[1] / "logs" / "join" / "join.log"),
        help="Path to the log file.",
    )
    args = parser.parse_args()

    main(
        args.arbetsstallen_csv,
        args.foretag_csv,
        args.output_csv,
        verbose=not args.quiet,
        log_path=Path(args.log_path),
    )
