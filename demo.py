import can
import time
import threading

from warden_server import UDSServer
from warden_attack import UDSClient, brute_force
from warden_detector import SecurityAccessDetector

CHANNEL = "demo"


def run_server(stop_event):
    server = UDSServer.__new__(UDSServer)
    server.bus = can.interface.Bus(channel=CHANNEL, interface="virtual")
    server.session = 0x01
    server.seed = None
    server.failed_attempts = 0
    server.locked_until = 0

    while not stop_event.is_set():
        msg = server.bus.recv(timeout=0.2)
        if msg:
            server.handle_message(msg)
    server.bus.shutdown()


def run_detector(stop_event, alerts):
    detector = SecurityAccessDetector.__new__(SecurityAccessDetector)
    detector.bus = can.interface.Bus(channel=CHANNEL, interface="virtual")
    detector.window = 15
    detector.threshold = 3
    from collections import deque
    detector.key_attempts = deque()
    detector.failed_key_attempts = deque()

    while not stop_event.is_set():
        msg = detector.bus.recv(timeout=0.2)
        if msg:
            alert = detector.process(msg)
            if alert:
                alerts.append(alert)
                print(alert)
    detector.bus.shutdown()


def main():
    stop_event = threading.Event()
    alerts = []

    server_thread = threading.Thread(target=run_server, args=(stop_event,))
    detector_thread = threading.Thread(target=run_detector, args=(stop_event, alerts))
    server_thread.start()
    detector_thread.start()

    time.sleep(0.3)

    print("running SecurityAccess brute-force against simulated ECU...\n")
    client = UDSClient.__new__(UDSClient)
    client.bus = can.interface.Bus(channel=CHANNEL, interface="virtual")
    brute_force(client, range(0, 10), delay=0.1)
    client.bus.shutdown()

    time.sleep(0.5)
    stop_event.set()
    server_thread.join()
    detector_thread.join()

    print(f"\ndemo complete. {len(alerts)} alert(s) raised during the attack.")


if __name__ == "__main__":
    main()
