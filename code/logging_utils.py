import logging
from pathlib import Path


def setup_logger(name: str, log_path: Path, verbose: bool = True) -> logging.Logger:
    """Configure a logger that writes to ``log_path`` and optionally to stdout."""
    logger = logging.getLogger(name)

    # Prevent duplicate handlers when reconfiguring within the same process.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    if verbose:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(logging.INFO)
        logger.addHandler(stream_handler)

    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger

