import sys
import os
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import can
from warden_detector import SecurityAccessDetector, SID_SECURITY_ACCESS, SUB_SEND_KEY, NEGATIVE_RESPONSE, REQ_ID, RESP_ID


def make_detector():
    d = SecurityAccessDetector.__new__(SecurityAccessDetector)
    d.bus = MagicMock()
    d.window = 15
    d.threshold = 3
    from collections import deque
    d.key_attempts = deque()
    d.failed_key_attempts = deque()
    return d


def make_msg(arb_id, data):
    return can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)


def test_no_alert_below_threshold():
    d = make_detector()
    msg = make_msg(REQ_ID, [SID_SECURITY_ACCESS, SUB_SEND_KEY, 0x00, 0x01])
    assert d.process(msg) is None
    assert d.process(msg) is None


def test_alert_on_repeated_key_attempts():
    d = make_detector()
    msg = make_msg(REQ_ID, [SID_SECURITY_ACCESS, SUB_SEND_KEY, 0x00, 0x01])
    d.process(msg)
    d.process(msg)
    alert = d.process(msg)
    assert alert is not None
    assert alert.severity == "WARNING"


def test_alert_on_repeated_negative_responses():
    d = make_detector()
    msg = make_msg(RESP_ID, [NEGATIVE_RESPONSE, SID_SECURITY_ACCESS, 0x35])
    d.process(msg)
    d.process(msg)
    alert = d.process(msg)
    assert alert is not None
    assert alert.severity == "CRITICAL"


def test_window_prunes_old_attempts():
    d = make_detector()
    d.window = 1
    msg = make_msg(REQ_ID, [SID_SECURITY_ACCESS, SUB_SEND_KEY, 0x00, 0x01])
    d.process(msg)
    d.process(msg)
    time.sleep(1.1)
    alert = d.process(msg)
    assert alert is None


def test_ignores_other_ids():
    d = make_detector()
    msg = make_msg(0x123, [0x10, 0x03])
    assert d.process(msg) is None
