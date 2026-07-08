import can
import time
import random

REQ_ID = 0x7E0
RESP_ID = 0x7E8

SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
SID_SECURITY_ACCESS = 0x27
NEGATIVE_RESPONSE = 0x7F

SESSION_DEFAULT = 0x01
SESSION_EXTENDED = 0x03

SUB_REQUEST_SEED = 0x01
SUB_SEND_KEY = 0x02

NRC_SUB_FUNCTION_NOT_SUPPORTED = 0x12
NRC_INVALID_KEY = 0x35
NRC_EXCEEDED_ATTEMPTS = 0x36
NRC_CONDITIONS_NOT_CORRECT = 0x22

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 10
XOR_MASK = 0x5A5A


class UDSServer:
    def __init__(self, channel="vcan0"):
        self.bus = can.interface.Bus(channel=channel, interface="socketcan")
        self.session = SESSION_DEFAULT
        self.seed = None
        self.failed_attempts = 0
        self.locked_until = 0

    def compute_key(self, seed):
        return seed ^ XOR_MASK

    def send_response(self, data):
        msg = can.Message(arbitration_id=RESP_ID, data=data, is_extended_id=False)
        self.bus.send(msg)

    def send_negative(self, sid, nrc):
        self.send_response([NEGATIVE_RESPONSE, sid, nrc])

    def handle_session_control(self, data):
        if len(data) < 2:
            self.send_negative(SID_DIAGNOSTIC_SESSION_CONTROL, NRC_CONDITIONS_NOT_CORRECT)
            return
        sub = data[1]
        if sub not in (SESSION_DEFAULT, SESSION_EXTENDED):
            self.send_negative(SID_DIAGNOSTIC_SESSION_CONTROL, NRC_SUB_FUNCTION_NOT_SUPPORTED)
            return
        self.session = sub
        self.send_response([SID_DIAGNOSTIC_SESSION_CONTROL + 0x40, sub])

    def handle_security_access(self, data):
        if len(data) < 2:
            self.send_negative(SID_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
            return
        sub = data[1]

        if time.time() < self.locked_until:
            self.send_negative(SID_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
            return

        if sub == SUB_REQUEST_SEED:
            self.seed = random.randint(1, 0xFFFF)
            seed_bytes = [self.seed >> 8 & 0xFF, self.seed & 0xFF]
            self.send_response([SID_SECURITY_ACCESS + 0x40, sub] + seed_bytes)
            return

        if sub == SUB_SEND_KEY:
            if len(data) < 4:
                self.send_negative(SID_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
                return
            if self.seed is None:
                self.send_negative(SID_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
                return

            key = (data[2] << 8) | data[3]
            expected = self.compute_key(self.seed)

            if key == expected:
                self.failed_attempts = 0
                self.seed = None
                self.send_response([SID_SECURITY_ACCESS + 0x40, sub])
            else:
                self.failed_attempts += 1
                self.seed = None
                if self.failed_attempts >= MAX_ATTEMPTS:
                    self.locked_until = time.time() + LOCKOUT_SECONDS
                    self.failed_attempts = 0
                    self.send_negative(SID_SECURITY_ACCESS, NRC_EXCEEDED_ATTEMPTS)
                else:
                    self.send_negative(SID_SECURITY_ACCESS, NRC_INVALID_KEY)
            return

        self.send_negative(SID_SECURITY_ACCESS, NRC_SUB_FUNCTION_NOT_SUPPORTED)

    def handle_message(self, msg):
        if msg.arbitration_id != REQ_ID:
            return
        data = msg.data
        if len(data) < 1:
            return
        sid = data[0]

        if sid == SID_DIAGNOSTIC_SESSION_CONTROL:
            self.handle_session_control(data)
        elif sid == SID_SECURITY_ACCESS:
            self.handle_security_access(data)

    def run(self):
        for msg in self.bus:
            self.handle_message(msg)


if __name__ == "__main__":
    UDSServer().run()
