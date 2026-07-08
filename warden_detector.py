import can
import time
import argparse
import logging
from collections import deque

REQ_ID = 0x7E0
RESP_ID = 0x7E8

SID_SECURITY_ACCESS = 0x27
SUB_SEND_KEY = 0x02
NEGATIVE_RESPONSE = 0x7F

WINDOW_SECONDS = 15
THRESHOLD = 3

SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_CRITICAL = "CRITICAL"

logger = logging.getLogger("warden_detector")


def setup_logging(logfile=None):
    handlers = [logging.StreamHandler()]
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        handlers=handlers,
    )


class Alert:
    def __init__(self, severity, message):
        self.severity = severity
        self.message = message
        self.timestamp = time.time()

    def __repr__(self):
        return f"[{self.severity}] {self.message}"


class SecurityAccessDetector:
    def __init__(self, channel="vcan0", window=WINDOW_SECONDS, threshold=THRESHOLD):
        self.bus = can.interface.Bus(channel=channel, interface="socketcan")
        self.window = window
        self.threshold = threshold
        self.key_attempts = deque()
        self.failed_key_attempts = deque()

    def prune(self, dq, now):
        while dq and now - dq[0] > self.window:
            dq.popleft()

    def handle_request(self, msg, now):
        if msg.arbitration_id != REQ_ID:
            return None
        data = msg.data
        if data[0] == SID_SECURITY_ACCESS and data[1] == SUB_SEND_KEY:
            self.key_attempts.append(now)
            self.prune(self.key_attempts, now)
            if len(self.key_attempts) >= self.threshold:
                return Alert(
                    SEVERITY_WARNING,
                    f"{len(self.key_attempts)} SecurityAccess key attempts in {self.window}s window",
                )
        return None

    def handle_response(self, msg, now):
        if msg.arbitration_id != RESP_ID:
            return None
        data = msg.data
        if data[0] == NEGATIVE_RESPONSE and data[1] == SID_SECURITY_ACCESS:
            self.failed_key_attempts.append(now)
            self.prune(self.failed_key_attempts, now)
            if len(self.failed_key_attempts) >= self.threshold:
                return Alert(
                    SEVERITY_CRITICAL,
                    f"probable SecurityAccess brute-force: {len(self.failed_key_attempts)} failures in {self.window}s",
                )
        return None

    def process(self, msg):
        now = time.time()
        alert = self.handle_request(msg, now)
        if alert:
            return alert
        return self.handle_response(msg, now)

    def run(self):
        for msg in self.bus:
            alert = self.process(msg)
            if alert:
                logger.warning(str(alert))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", default="vcan0")
    parser.add_argument("--window", type=float, default=WINDOW_SECONDS)
    parser.add_argument("--threshold", type=int, default=THRESHOLD)
    parser.add_argument("--logfile", default=None)
    args = parser.parse_args()

    setup_logging(args.logfile)
    SecurityAccessDetector(args.channel, args.window, args.threshold).run()
