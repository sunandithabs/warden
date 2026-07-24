[![Tests](https://github.com/sunandithabs/WARDEN/actions/workflows/tests.yml/badge.svg)](https://github.com/sunandithabs/WARDEN/actions/workflows/tests.yml)

# WARDEN

Weak authentication and rogue diagnostic session event notifier.

A UDS (ISO 14229) diagnostic session security simulator over SocketCAN. Brute-forces a weak seed-key handshake and detects the attack live.

## Components

- `warden_server.py` : simulated ECU diagnostic responder. Implements DiagnosticSessionControl (0x10) and SecurityAccess (0x27), with a deliberately weak XOR seed-key scheme and a basic attempt lockout, similar to how some real OEM implementations have been found to work.
- `warden_attack.py` : client that opens an extended diagnostic session and brute-forces the SecurityAccess key.
- `warden_detector.py` : watches bus traffic and flags SecurityAccess abuse, repeated key attempts and repeated negative responses within a sliding time window.

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

Runs the server, detector, and a brute-force attack together over an in-process virtual CAN bus, so you can see detection trigger without setting up vcan0.

## Tests

```
pytest tests/
```

## Notes

The XOR seed-key algorithm is intentionally weak, built for demonstration. It is not representative of production automotive security algorithms, which typically use proprietary or cryptographic key derivation.
