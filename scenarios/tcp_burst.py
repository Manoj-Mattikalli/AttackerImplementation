def execute_tcp_burst(target, port, count):

    print("\n==========================================")
    print("        TCP BURST SCENARIO")
    print("==========================================")

    print(f"Target : {target}")
    print(f"Port   : {port}")
    print(f"Count  : {count}")

    return {
        "success": True,
        "status": "READY",
        "attack_type": "TCP_BURST",
        "target": target,
        "port": port,
        "count": count
    }