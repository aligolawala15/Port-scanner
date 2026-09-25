import json
import csv
import os
from datetime import datetime


def save_json(target, ip, ports):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"reports/scan_{timestamp}.json"
    )

    data = {
        "target": target,
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "open_ports": ports
    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )

    return filename


def save_csv(target, ip, ports):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"reports/scan_{timestamp}.csv"
    )

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Target",
            "IP Address",
            "Port"
        ])

        for port in ports:

            writer.writerow([
                target,
                ip,
                port
            ])

    return filename