[![Tests](https://github.com/sunandithabs/WARDEN/actions/workflows/tests.yml/badge.svg)](https://github.com/sunandithabs/WARDEN/actions/workflows/tests.yml)

weak authentication & rogue diagnostic-session event notifier

a uds (iso 14229) diagnostic session security simulator over socketcan. brute-forces a weak seed-key handshake and detects the attack live.

components


warden_server.py — simulated ecu diagnostic responder. implements diagnosticsessioncontrol (0x10) and securityaccess (0x27), with a deliberately weak xor seed-key scheme and a basic attempt lockout, similar to how some real oem implementations have been found to work.
warden_attack.py — client that opens an extended diagnostic session and brute-forces the securityaccess key.
warden_detector.py — watches bus traffic and flags securityaccess abuse: repeated key attempts and repeated negative responses within a sliding time window.


setup

sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

pip install -r requirements.txt

run

python warden_server.py
python warden_detector.py
python warden_attack.py --attempts 20

quick demo (no vcan0 setup required)

python demo.py

runs server, detector, and a brute-force attack together over an in-process virtual can bus, so you can see detection trigger without setting up vcan0.

tests

pytest tests/

notes

the xor seed-key algorithm is intentionally weak, built for demonstration. it's not representative of production automotive security algorithms, which typically use proprietary or cryptographic key derivation.
