import logging


class NetworkLogger:
    def __init__(self, log_file: str = "net_traffic.log") -> None:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s | %(message)s",
        )

    def log_info(self, message: str) -> None:
        logging.info(message)

    def log_alert(self, message: str) -> None:
        logging.warning(message)
