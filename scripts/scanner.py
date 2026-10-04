import subprocess
import json
from datetime import datetime
from pathlib import Path

from logger import log_attack


# ==========================================
# PATH CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_FILE = PROJECT_ROOT / "config.json"

SCANS_FOLDER = PROJECT_ROOT / "scans"


# ==========================================
# LOAD CONFIGURATION
# ==========================================

with open(
    CONFIG_FILE,
    "r",
    encoding="utf-8"
) as file:

    config = json.load(file)


TARGET = config["target"]
PORTS = config["ports"]
SCAN_TYPE = config["scan_type"]


# ==========================================
# PORT VALIDATION
# ==========================================

def validate_ports(ports):

    if not isinstance(ports, str):

        raise ValueError(
            "Ports must be provided as a string."
        )

    ports = ports.strip()

    if not ports:

        raise ValueError(
            "Port specification cannot be empty."
        )

    # Nmap supports:
    #
    # 8080
    # 8000-8100
    # 80,443,8080
    # 80,443,8000-8100

    parts = ports.split(",")

    for part in parts:

        part = part.strip()

        if not part:

            raise ValueError(
                "Invalid empty port value."
            )


        # ==========================================
        # PORT RANGE
        # ==========================================

        if "-" in part:

            range_parts = part.split("-")

            if len(range_parts) != 2:

                raise ValueError(
                    f"Invalid port range: {part}"
                )

            start, end = range_parts

            if not start.isdigit() or not end.isdigit():

                raise ValueError(
                    f"Invalid port range: {part}"
                )

            start = int(start)
            end = int(end)

            if start < 1 or end > 65535:

                raise ValueError(
                    f"Port range out of bounds: {part}"
                )

            if start > end:

                raise ValueError(
                    f"Port range is reversed: {part}"
                )


        # ==========================================
        # SINGLE PORT
        # ==========================================

        else:

            if not part.isdigit():

                raise ValueError(
                    f"Invalid port: {part}"
                )

            port = int(part)

            if port < 1 or port > 65535:

                raise ValueError(
                    f"Port out of bounds: {port}"
                )

    return True


# ==========================================
# TARGET VALIDATION
# ==========================================

def validate_target(target):

    if not isinstance(target, str):

        raise ValueError(
            "Target must be provided as a string."
        )

    target = target.strip()

    if not target:

        raise ValueError(
            "Target cannot be empty."
        )

    if any(character.isspace() for character in target):

        raise ValueError(
            "Target cannot contain spaces."
        )


    # ==========================================
    # BASIC IPv4 VALIDATION
    # ==========================================

    parts = target.split(".")

    if len(parts) == 4:

        if all(part.isdigit() for part in parts):

            for part in parts:

                value = int(part)

                if value < 0 or value > 255:

                    raise ValueError(
                        f"Invalid IPv4 address: {target}"
                    )

            return True


    # ==========================================
    # HOSTNAME VALIDATION
    # ==========================================

    allowed_characters = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "-_."
    )

    if not all(
        character in allowed_characters
        for character in target
    ):

        raise ValueError(
            f"Invalid target: {target}"
        )

    return True

# ==========================================
# NMAP RESULT PARSER
# ==========================================

def parse_nmap_output(output):

    result = {
        "host_status": "UNKNOWN",
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "closed_count": 0,
        "filtered_count": 0
    }

    lines = output.splitlines()

    for line in lines:

        line = line.strip()


        # ==========================================
        # HOST STATUS
        # ==========================================

        if "Host is up" in line:

            result["host_status"] = "UP"


        elif "Host is down" in line:

            result["host_status"] = "DOWN"


        # ==========================================
        # EXPLICIT PORT INFORMATION
        # ==========================================

        elif (
            "/" in line
            and (
                "open" in line
                or "closed" in line
                or "filtered" in line
            )
        ):

            parts = line.split()

            if len(parts) >= 2:

                port_protocol = parts[0]
                state = parts[1]


                if state == "open":

                    result["open_ports"].append(
                        port_protocol
                    )


                elif state == "closed":

                    result["closed_ports"].append(
                        port_protocol
                    )


                elif state == "filtered":

                    result["filtered_ports"].append(
                        port_protocol
                    )


        # ==========================================
        # NMAP SUMMARY
        # ==========================================

        elif line.startswith("Not shown:"):

            parts = line.split()

            if len(parts) >= 4:

                try:

                    count = int(parts[2])

                    if "closed" in line:

                        result["closed_count"] += count


                    if "filtered" in line:

                        result["filtered_count"] += count

                except ValueError:

                    pass


    # ==========================================
    # INCLUDE EXPLICIT PORTS IN COUNTS
    # ==========================================

    result["closed_count"] += len(
        result["closed_ports"]
    )

    result["filtered_count"] += len(
        result["filtered_ports"]
    )


    return result

# ==========================================
# CREATE ATTACK RESULT
# ==========================================

def create_attack_result(
    success,
    status,
    target,
    ports,
    scan_type,
    return_code=None,
    output_file=None,
    scan_result=None,
    error=None
):

    return {
        "success": success,
        "status": status,
        "attack_type": "PORT_SCAN",
        "target": target,
        "ports": ports,
        "scan_type": scan_type,
        "return_code": return_code,
        "output_file": output_file,
        "scan_result": scan_result,
        "error": error
    }

# ==========================================
# PORT SCANNER
# ==========================================

def run_port_scan(target, ports, scan_type):

    # ==========================================
    # VALIDATE TARGET
    # ==========================================

    validate_target(target)


    # ==========================================
    # VALIDATE PORTS
    # ==========================================

    validate_ports(ports)


    # ==========================================
    # CREATE OUTPUT FILE
    # ==========================================

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    SCANS_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        SCANS_FOLDER /
        f"port_scan_{timestamp}.txt"
    )


    # ==========================================
    # SCAN TYPE
    # ==========================================

    if scan_type == "tcp_connect":

        scan_option = "-sT"

    else:

        raise ValueError(
            f"Unsupported scan type: {scan_type}"
        )


    # ==========================================
    # NMAP COMMAND
    # ==========================================

    command = [
        "nmap",
        scan_option,
        "-p",
        ports,
        target
    ]


    # ==========================================
    # DISPLAY SCAN INFORMATION
    # ==========================================

    print("\n==========================================")
    print("         ATTACKER - PORT SCAN")
    print("==========================================")

    print(f"Target : {target}")
    print(f"Ports  : {ports}")
    print()

    print("Executing:")
    print(" ".join(command))
    print()


    # ==========================================
    # EXECUTE NMAP
    # ==========================================

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=120
        )


        # ==========================================
        # SAVE NMAP OUTPUT
        # ==========================================

        output_file.write_text(
            result.stdout + "\n" + result.stderr,
            encoding="utf-8"
        )

        # ==========================================
        # PARSE NMAP RESULT
        # ==========================================

        parsed_result = parse_nmap_output(
            result.stdout
        )

        # ==========================================
        # DISPLAY PARSED RESULT
        # ==========================================

        print("\n==========================================")
        print("         PARSED SCAN RESULT")
        print("==========================================")

        print(
            f"Host Status : "
            f"{parsed_result['host_status']}"
        )

        print(
            f"Open Ports  : "
            f"{parsed_result['open_ports']}"
        )

        print(
            f"Closed Ports: "
            f"{parsed_result['closed_ports']}"
        )

        print(
            f"Closed Count: "
            f"{parsed_result['closed_count']}"
        )

        print(
            f"Filtered Ports: "
            f"{parsed_result['filtered_ports']}"
        )

        print(
            f"Filtered Count: "
            f"{parsed_result['filtered_count']}"
        )

        # ==========================================
        # DETERMINE STATUS
        # ==========================================

        status = (
            "COMPLETED"
            if result.returncode == 0
            else "FAILED"
        )


        # ==========================================
        # LOG ATTACK
        # ==========================================

        log_attack(
            attack_type="PORT_SCAN",
            target=target,
            ports=ports,
            scan_type=scan_type,
            command=" ".join(command),
            status=status
        )


        # ==========================================
        # DISPLAY RESULT
        # ==========================================

        if result.returncode != 0:

            print("ERROR: Nmap scan failed.")

            print(
                f"Nmap return code: "
                f"{result.returncode}"
            )

            if result.stderr.strip():

                print("\nNmap error:")
                print(result.stderr)

        else:

            print(result.stdout)


        print("------------------------------------------")
        print("Scan result saved to:")
        print(output_file)
        print("------------------------------------------")


        # ==========================================
        # RETURN RESULT
        # ==========================================

        return create_attack_result(
            success=result.returncode == 0,
            status=status,
            target=target,
            ports=ports,
            scan_type=scan_type,
            return_code=result.returncode,
            output_file=str(output_file),
            scan_result=parsed_result,
            error=None
        )

    # ==========================================
    # NMAP TIMEOUT
    # ==========================================

    except subprocess.TimeoutExpired:

        print("\nERROR: Nmap scan timed out.")

        print(
            "The scan exceeded "
            "the 120-second limit."
        )


        log_attack(
            attack_type="PORT_SCAN",
            target=target,
            ports=ports,
            scan_type=scan_type,
            command=" ".join(command),
            status="TIMEOUT"
        )


        return create_attack_result(
            success=False,
            status="TIMEOUT",
            target=target,
            ports=ports,
            scan_type=scan_type,
            return_code=None,
            output_file=None,
            scan_result=None,
            error="Nmap scan timed out"
        )

    # ==========================================
    # NMAP NOT FOUND
    # ==========================================

    except FileNotFoundError:

        print("\nERROR: Nmap was not found.")

        print(
            "Make sure Nmap is installed "
            "and available in PATH."
        )


        log_attack(
            attack_type="PORT_SCAN",
            target=target,
            ports=ports,
            scan_type=scan_type,
            command=" ".join(command),
            status="NMAP_NOT_FOUND"
        )


        return create_attack_result(
            success=False,
            status="NMAP_NOT_FOUND",
            target=target,
            ports=ports,
            scan_type=scan_type,
            return_code=None,
            output_file=None,
            scan_result=None,
            error="Nmap executable not found"
        )

    # ==========================================
    # OTHER OS EXECUTION ERROR
    # ==========================================

    except OSError as error:

        print("\nERROR: Could not execute Nmap.")

        print(
            f"Details: {error}"
        )


        log_attack(
            attack_type="PORT_SCAN",
            target=target,
            ports=ports,
            scan_type=scan_type,
            command=" ".join(command),
            status="EXECUTION_ERROR"
        )


        return create_attack_result(
            success=False,
            status="EXECUTION_ERROR",
            target=target,
            ports=ports,
            scan_type=scan_type,
            return_code=None,
            output_file=None,
            scan_result=None,
            error=str(error)
        )


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    run_port_scan(
        TARGET,
        PORTS,
        SCAN_TYPE
    )
    