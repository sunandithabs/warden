# WARDEN

**W**eak **A**uthentication & **R**ogue **D**iagnostic-session **E**vent **N**otifier

A UDS (ISO 14229) diagnostic session security simulator over SocketCAN. Demonstrates a SecurityAccess seed-key brute-force attack and real-time detection of the exploit attempt.

## Components

- `warden_server.py` — simulated ECU diagnostic responder. Implements DiagnosticSessionControl (0x10) and SecurityAccess (0x27) with a deliberately weak XOR seed-key scheme and a basic attempt lockout, mirroring how some real OEM implementations have been found to work.
- `warden_attack.py` — client that opens an extended diagnostic session and brute-forces the SecurityAccess key.
- `warden_detector.py` — sniffs bus traffic and flags SecurityAccess abuse: repeated key attempts and repeated negative responses within a sliding time window.

## Setup

```
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

pip install -r requirements.txt
```

## Run

```
python warden_server.py
python warden_detector.py
python warden_attack.py --attempts 20
```

## Quick demo (no vcan0 setup required)

```
python demo.py
```

Runs server, detector, and a brute-force attack together over an in-process virtual CAN bus, showing detection triggering live.

## Tests

```
pytest tests/
```

## Notes

The XOR seed-key algorithm is intentionally weak for demonstration. It is not representative of production automotive security algorithms, which typically use proprietary or cryptographic key derivation.
