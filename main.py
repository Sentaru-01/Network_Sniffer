from pathlib import Path

import yaml

from sniffer.core import RawSniffer
from sniffer.detector import AnomalyDetector
from sniffer.logger import NetworkLogger


def load_config(path: str = "config.yaml") -> dict:
    config_path = Path(__file__).parent / path
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main() -> None:
    config = load_config()

    logger = NetworkLogger(log_file=config["log_file"])
    detector = AnomalyDetector(
        critical_ports=set(config["critical_ports"]),
        max_icmp_payload=config["icmp"]["max_payload"],
        icmp_threshold=config["icmp"]["threshold"],
        time_window=config["icmp"]["time_window"],
    )
    sniffer = RawSniffer(
        host=config["host"],
        detector=detector,
        logger=logger,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
