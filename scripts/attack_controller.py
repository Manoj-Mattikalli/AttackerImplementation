import json
import sys
from pathlib import Path


# ==========================================
# PROJECT PATH
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_ROOT))


# ==========================================
# IMPORTS
# ==========================================

from scenarios.port_scan import execute_port_scan
from scenarios.tcp_burst import execute_tcp_burst


# ==========================================
# SCENARIO REGISTRY
# ==========================================

SCENARIOS = {
    "1": {
        "name": "Port Scan",
        "handler": execute_port_scan,
        "requires": [
            "target",
            "ports",
            "scan_type",
            "scan_rounds",
            "delay_between_rounds"
        ]
    },

    "2": {
        "name": "TCP Burst",
        "handler": execute_tcp_burst,
        "requires": [
            "target",
            "port",
            "count"
        ]
    }
}


# ==========================================
# VALIDATE SCENARIO REGISTRY
# ==========================================

for key, scenario in SCENARIOS.items():

    if "name" not in scenario:

        print(
            f"\nERROR: Scenario {key} "
            f"is missing a name."
        )

        sys.exit(1)

    if "handler" not in scenario:

        print(
            f"\nERROR: Scenario {key} "
            f"is missing a handler."
        )

        sys.exit(1)

    if "requires" not in scenario:

        print(
            f"\nERROR: Scenario {key} "
            f"is missing required parameters."
        )

        sys.exit(1)


# ==========================================
# VALIDATE SCENARIO REQUIREMENTS
# ==========================================

def validate_scenario_requirements(
    scenario_key,
    scenario,
    config
):

    required_parameters = scenario.get(
        "requires",
        []
    )

    missing_parameters = [
        parameter
        for parameter in required_parameters
        if parameter not in config
    ]

    if missing_parameters:

        print(
            f"\nERROR: Scenario "
            f"{scenario_key} is missing "
            f"required configuration:"
        )

        for parameter in missing_parameters:

            print(
                f" - {parameter}"
            )

        return False

    return True


# ==========================================
# CONFIGURATION
# ==========================================

CONFIG_FILE = PROJECT_ROOT / "config.json"


# ==========================================
# LOAD CONFIGURATION
# ==========================================

try:

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        config = json.load(file)


except FileNotFoundError:

    print(
        "\nERROR: Configuration file not found:"
    )

    print(CONFIG_FILE)

    sys.exit(1)


except json.JSONDecodeError:

    print(
        "\nERROR: config.json contains invalid JSON."
    )

    sys.exit(1)


# ==========================================
# VALIDATE REQUIRED CONFIGURATION FIELDS
# ==========================================

REQUIRED_FIELDS = [
    "target",
    "ports",
    "scan_type"
]


missing_fields = [
    field
    for field in REQUIRED_FIELDS
    if field not in config
]


if missing_fields:

    print(
        "\nERROR: Missing configuration fields:"
    )

    for field in missing_fields:

        print(
            f" - {field}"
        )

    sys.exit(1)


# ==========================================
# READ CONFIGURATION VALUES
# ==========================================

TARGET = config["target"]

PORTS = config["ports"]

SCAN_TYPE = config["scan_type"]


# ==========================================
# VALIDATE BASIC CONFIGURATION VALUES
# ==========================================

if not isinstance(TARGET, str) or not TARGET.strip():

    print(
        "\nERROR: Target cannot be empty."
    )

    sys.exit(1)


if not isinstance(PORTS, str) or not PORTS.strip():

    print(
        "\nERROR: Ports cannot be empty."
    )

    sys.exit(1)


# ==========================================
# VALIDATE SCAN TYPE
# ==========================================

SUPPORTED_SCAN_TYPES = [
    "tcp_connect"
]


if SCAN_TYPE not in SUPPORTED_SCAN_TYPES:

    print(
        "\nERROR: Unsupported scan type."
    )

    print(
        f"Received: {SCAN_TYPE}"
    )

    print(
        "Supported scan types:",
        ", ".join(SUPPORTED_SCAN_TYPES)
    )

    sys.exit(1)


# ==========================================
# VALIDATE PORT SCAN SETTINGS
# ==========================================

if "scan_rounds" in config:

    scan_rounds = config["scan_rounds"]

    if (
        not isinstance(scan_rounds, int)
        or isinstance(scan_rounds, bool)
    ):

        print(
            "\nERROR: scan_rounds must be "
            "an integer."
        )

        sys.exit(1)

    if scan_rounds < 1:

        print(
            "\nERROR: scan_rounds must be "
            "at least 1."
        )

        sys.exit(1)

else:

    print(
        "\nERROR: scan_rounds is missing "
        "from config.json."
    )

    sys.exit(1)


if "delay_between_rounds" in config:

    delay_between_rounds = config[
        "delay_between_rounds"
    ]

    if (
        not isinstance(
            delay_between_rounds,
            (int, float)
        )
        or isinstance(delay_between_rounds, bool)
    ):

        print(
            "\nERROR: delay_between_rounds "
            "must be a number."
        )

        sys.exit(1)

    if delay_between_rounds < 0:

        print(
            "\nERROR: delay_between_rounds "
            "cannot be negative."
        )

        sys.exit(1)

else:

    print(
        "\nERROR: delay_between_rounds "
        "is missing from config.json."
    )

    sys.exit(1)


# ==========================================
# MENU
# ==========================================

def show_menu():

    print(
        "\n=========================================="
    )

    print(
        "          AI ATTACKER SIMULATOR"
    )

    print(
        "=========================================="
    )

    print(
        "\nAvailable Attack Scenarios:"
    )

    for key, scenario in SCENARIOS.items():

        print(
            f"{key}. "
            f"{scenario['name']}"
        )

    exit_option = len(SCENARIOS) + 1

    print(
        f"{exit_option}. Exit"
    )


# ==========================================
# MAIN
# ==========================================

def main():

    while True:

        show_menu()

        choice = input(
            "\nSelect attack: "
        ).strip()


        # ==================================
        # EXIT
        # ==================================

        exit_option = str(
            len(SCENARIOS) + 1
        )

        if choice == exit_option:

            print(
                "\nExiting attacker..."
            )

            break


        # ==================================
        # ATTACK SCENARIO
        # ==================================

        elif choice in SCENARIOS:

            scenario = SCENARIOS[choice]


            # ==================================
            # VALIDATE REQUIREMENTS
            # ==================================

            if not validate_scenario_requirements(
                choice,
                scenario,
                config
            ):

                continue


            print(
                f"\nStarting "
                f"{scenario['name']} Scenario..."
            )


            # ==================================
            # PREPARE SCENARIO PARAMETERS
            # ==================================

            scenario_arguments = []

            for parameter in scenario["requires"]:

                scenario_arguments.append(
                    config[parameter]
                )


            # ==================================
            # EXECUTE SCENARIO
            # ==================================

            result = scenario["handler"](
                *scenario_arguments
            )


            # ==================================
            # DISPLAY FINAL STATUS
            # ==================================

            if result.get("success"):

                print(
                    "\n[+] Scenario completed successfully."
                )

            else:

                print(
                    "\n[!] Scenario completed "
                    "with errors."
                )


        # ==================================
        # INVALID OPTION
        # ==================================

        else:

            print(
                "\nInvalid choice. "
                "Please select a valid attack."
            )


# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == "__main__":

    main()
