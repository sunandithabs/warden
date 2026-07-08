import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import can
from warden_detector import SecurityAccessDetector, SID_SECURITY_ACCESS, SUB_SEND_KEY, REQ_ID


def test_detector_flags_over_virtual_bus():
    sender = can.interface.Bus(channel="test_ch", interface="virtual")
    listener = can.interface.Bus(channel="test_ch", interface="virtual")

    from collections import deque
    detector = SecurityAccessDetector.__new__(SecurityAccessDetector)
    detector.bus = listener
    detector.window = 15
    detector.threshold = 3
    detector.key_attempts = deque()
    detector.failed_key_attempts = deque()

    msg = can.Message(
        arbitration_id=REQ_ID,
        data=[SID_SECURITY_ACCESS, SUB_SEND_KEY, 0x00, 0x01],
        is_extended_id=False,
    )

    alerts = []
    for _ in range(3):
        sender.send(msg)
        received = listener.recv(timeout=1.0)
        alert = detector.process(received)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    assert alerts[0].severity == "WARNING"

    sender.shutdown()
    listener.shutdown()
