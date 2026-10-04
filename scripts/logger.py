from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOGS_FOLDER = PROJECT_ROOT / "logs"

LOG_FILE = LOGS_FOLDER / "attacks.log"


def log_attack(
    attack_type,
    target,
    ports,
    scan_type,
    command,
    status
):

    LOGS_FOLDER.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    log_entry = (
        f"{timestamp} | "
        f"{attack_type} | "
        f"Target={target} | "
        f"Ports={ports} | "
        f"ScanType={scan_type} | "
        f"Command={command} | "
        f"Status={status}\n"
    )

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(log_entry)