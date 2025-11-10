import configparser
import logging
import re
import sys
from pathlib import Path
from typing import List, Sequence

from code import arbetsstallen, foretag, join
from code.logging_utils import setup_logger

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "main.conf"


def parse_list(value: str) -> List[str]:
    parts = re.split(r"[\s,]+", value.strip()) if value else []
    return [item for item in parts if item]


def parse_int_list(value: str) -> List[int]:
    parts = re.split(r"[\s,;]+", value.strip()) if value else []
    return [int(token) for token in parts if token]


def parse_duration_days(value: str) -> int:
    token = value.strip().lower()
    if not token:
        raise ValueError("Duration value cannot be empty.")
    if token.endswith("m"):
        return int(token[:-1]) * 30
    if token.endswith("d"):
        return int(token[:-1])
    return int(token)


def resolve_path(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        return BASE_DIR / path
    return path


def load_config(config_path: Path) -> dict:
    config = configparser.ConfigParser()
    if not config.read(config_path, encoding="utf-8"):
        raise FileNotFoundError(f"Configuration file not found at {config_path}")

    pipeline_cfg = config["pipeline"]
    logging_cfg = config["logging"]

    target_sni_codes = parse_list(pipeline_cfg.get("target_sni_codes", ""))
    if not target_sni_codes:
        raise ValueError("Configuration must supply at least one SNI code.")

    avdelning_token = pipeline_cfg.get("arbetsstallen_avdelning", "").strip().upper()
    avdelning_code = avdelning_token or None

    sni_csv_value = pipeline_cfg.get("arbetsstallen_sni_csv", "").strip()
    if sni_csv_value:
        sni_csv_path = resolve_path(sni_csv_value)
    else:
        sni_csv_path = resolve_path("sni.csv")

    bransch_levels = parse_int_list(pipeline_cfg.get("arbetsstallen_bransch_levels", ""))
    if not bransch_levels:
        raise ValueError("Configuration must specify at least one bransch level (1-3).")

    if any(level not in {1, 2, 3} for level in bransch_levels):
        raise ValueError("Bransch levels must be within the set {1, 2, 3}.")

    start_zip = pipeline_cfg.getint("arbetsstallen_start_zip", fallback=0)
    end_zip = pipeline_cfg.getint("arbetsstallen_end_zip", fallback=99999)

    foretag_cache_max_age_days = parse_duration_days(pipeline_cfg.get("foretag_cache_max_age", "30d"))

    verbose = pipeline_cfg.getboolean("verbose", fallback=True)

    config_data = {
        "target_sni_codes": target_sni_codes,
        "bransch_levels": bransch_levels,
        "start_zip": start_zip,
        "end_zip": end_zip,
        "foretag_cache_max_age_days": foretag_cache_max_age_days,
        "arbetsstallen_avdelning": avdelning_code,
        "arbetsstallen_sni_csv": sni_csv_path,
        "verbose": verbose,
        "arbetsstallen_output": resolve_path(pipeline_cfg["arbetsstallen_output"]),
        "foretag_output": resolve_path(pipeline_cfg["foretag_output"]),
        "join_output": resolve_path(pipeline_cfg["join_output"]),
        "foretag_cache": resolve_path(pipeline_cfg["foretag_cache_file"]),
        "main_log": resolve_path(logging_cfg.get("main_log", "main.log")),
        "arbetsstallen_log": resolve_path(logging_cfg.get("arbetsstallen_log", "logs/arbetsstallen/arbetsstallen.log")),
        "foretag_log": resolve_path(logging_cfg.get("foretag_log", "logs/foretag/foretag.log")),
        "join_log": resolve_path(logging_cfg.get("join_log", "logs/join/join.log")),
    }

    return config_data


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def run_pipeline(config: dict, config_path: Path) -> None:
    verbose = config["verbose"]
    main_logger = setup_logger("pipeline.main", config["main_log"], verbose)
    main_logger.info("Starting pipeline with configuration from %s", config_path)

    try:
        ensure_parent(config["arbetsstallen_output"])
        ensure_parent(config["foretag_output"])
        ensure_parent(config["join_output"])

        main_logger.info("Step 1/3: arbetsstallen")
        arbetsstallen.main(
            str(config["arbetsstallen_output"]),
            verbose=verbose,
            start_zip=config["start_zip"],
            end_zip=config["end_zip"],
            target_sni_codes=config["target_sni_codes"],
            bransch_levels=config["bransch_levels"],
            log_path=config["arbetsstallen_log"],
            avdelning_code=config["arbetsstallen_avdelning"],
            sni_csv_path=config["arbetsstallen_sni_csv"],
        )

        main_logger.info("Step 2/3: foretag")
        foretag.main(
            str(config["arbetsstallen_output"]),
            str(config["foretag_output"]),
            verbose=verbose,
            cache_path=config["foretag_cache"],
            cache_max_age_days=config["foretag_cache_max_age_days"],
            log_path=config["foretag_log"],
        )

        main_logger.info("Step 3/3: join")
        join.main(
            str(config["arbetsstallen_output"]),
            str(config["foretag_output"]),
            str(config["join_output"]),
            verbose=verbose,
            log_path=config["join_log"],
        )

        main_logger.info("Pipeline completed successfully.")

    except Exception as exc:  # pylint: disable=broad-except
        main_logger.exception("Pipeline failed: %s", exc)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    config_path = CONFIG_PATH
    if argv:
        config_path = resolve_path(argv[0])

    config = load_config(config_path)
    run_pipeline(config, config_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
