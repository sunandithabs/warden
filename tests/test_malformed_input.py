import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import can
from warden_server import UDSServer, REQ_ID, SID_SECURITY_ACCESS, SID_DIAGNOSTIC_SESSION_CONTROL


def make_server():
    s = UDSServer.__new__(UDSServer)
    s.bus = MagicMock()
    s.session = 0x01
    s.seed = None
    s.failed_attempts = 0
    s.locked_until = 0
    return s


def make_msg(data):
    return can.Message(arbitration_id=REQ_ID, data=data, is_extended_id=False)


def test_empty_frame_does_not_crash():
    s = make_server()
    s.handle_message(make_msg([]))


def test_short_session_control_frame_does_not_crash():
    s = make_server()
    s.handle_message(make_msg([SID_DIAGNOSTIC_SESSION_CONTROL]))
    s.bus.send.assert_called_once()


def test_short_security_access_seed_send_key_does_not_crash():
    s = make_server()
    s.seed = 0x1234
    s.handle_message(make_msg([SID_SECURITY_ACCESS, 0x02, 0x00]))
    s.bus.send.assert_called_once()
