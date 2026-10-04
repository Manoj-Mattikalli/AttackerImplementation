import time

from scripts.scanner import run_port_scan


# ==========================================
# PORT SCAN SCENARIO
# ==========================================

def execute_port_scan(
    target,
    ports,
    scan_type,
    scan_rounds=1,
    delay_between_rounds=0
):

    print("\n==================================================")
    print("             AI ATTACKER SIMULATOR")
    print("==================================================")

    print("\nATTACK: TCP PORT SCAN")
    print("------------------------------------------")

    print(f"Target        : {target}")
    print(f"Port Range    : {ports}")
    print(f"Engine        : Nmap")
    print(f"Method        : {scan_type}")
    print(f"Scan Rounds   : {scan_rounds}")
    print(
        f"Interval      : "
        f"{delay_between_rounds} seconds"
    )

    print("\n[+] Attack initialized")
    print("[+] Nmap engine selected")
    print("[+] Beginning scan traffic generation...")

    results = []

    for round_number in range(
        1,
        scan_rounds + 1
    ):

        print("\n==================================================")
        print(
            f"ROUND {round_number} / "
            f"{scan_rounds}"
        )
        print("==================================================")

        print(
            "[+] Generating TCP scan traffic..."
        )

        result = run_port_scan(
            target,
            ports,
            scan_type
        )

        results.append(result)

        print(
            f"\n[+] Round {round_number} "
            f"completed"
        )

        print(
            f"[+] Status: "
            f"{result.get('status')}"
        )

        if result.get("error"):

            print(
                f"[!] Error: "
                f"{result.get('error')}"
            )

        if (
            round_number < scan_rounds
            and delay_between_rounds > 0
        ):

            print(
                f"\n[*] Waiting "
                f"{delay_between_rounds} seconds "
                f"before next round..."
            )

            time.sleep(
                delay_between_rounds
            )

    display_attack_report(
        target,
        ports,
        scan_type,
        scan_rounds,
        delay_between_rounds,
        results
    )

    return {
        "success": all(
            result.get("success", False)
            for result in results
        ),
        "status": "COMPLETED",
        "attack_type": "PORT_SCAN",
        "target": target,
        "ports": ports,
        "scan_type": scan_type,
        "scan_rounds": scan_rounds,
        "delay_between_rounds": delay_between_rounds,
        "results": results
    }


# ==========================================
# DISPLAY ATTACK REPORT
# ==========================================

def display_attack_report(
    target,
    ports,
    scan_type,
    scan_rounds,
    delay_between_rounds,
    results
):

    print("\n==================================================")
    print("               ATTACK SUMMARY")
    print("==================================================")

    print(
        f"Attack Type    : PORT_SCAN"
    )

    print(
        f"Target         : {target}"
    )

    print(
        f"Port Range     : {ports}"
    )

    print(
        f"Engine         : Nmap"
    )

    print(
        f"Scan Method    : {scan_type}"
    )

    print(
        f"Rounds         : {scan_rounds}"
    )

    print(
        f"Interval       : "
        f"{delay_between_rounds} seconds"
    )

    print("\nRound Results")
    print("------------------------------------------")

    successful_rounds = 0
    failed_rounds = 0

    for index, result in enumerate(
        results,
        start=1
    ):

        status = result.get(
            "status",
            "UNKNOWN"
        )

        print(
            f"Round {index} : "
            f"{status}"
        )

        if result.get("success", False):
            successful_rounds += 1
        else:
            failed_rounds += 1

    print("------------------------------------------")

    print(
        f"Successful Rounds : "
        f"{successful_rounds}"
    )

    print(
        f"Failed Rounds     : "
        f"{failed_rounds}"
    )

    if failed_rounds == 0:

        print(
            "\n[+] Attack scenario "
            "completed successfully."
        )

    else:

        print(
            "\n[!] Attack scenario "
            "completed with errors."
        )

    print("==================================================")