#!/usr/bin/env python3
"""Starter template for the port knocking client."""

import argparse
import socket
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.3


def send_knock(target, port, delay):
    """Send a single knock to the target port."""
    try:
        # USE UDP SOCKETS BECAUSE WE DON'T NEED A RESPONSE AND ONLY NEED TO HIT THE FIREWALL
        # TCP REQUIRES A RESPONSE (ACK) THAT WILL NEVER COME -> SLOW DOWN THE KNOCKING PROCESS

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)

        # THE PAYLOAD THAT'S SENT IS IRRELIEVENT -> SOMETHING JUST NEEDS TO PING THE CORRECT PORTS
        sock.sendto(b'KNOCK', (target, int(port)))
        sock.close()

    except Exception as e:
        print(f"ERROR KNOCKING FOR {port}: {e}")

    time.sleep(delay)   # THERE NEEDS TO BE A SMALL DELAY BECAUSE WITH UDP THE PACKETS MAY NOT ARRIVE IN ORDER (NO ACKS) SO A SMALL DELAY ENSURE ORDERNESS TO A VERY HIGH DEGREE


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence."""
    for port in sequence:
        send_knock(target, port, delay)


def check_protected_port(target, protected_port):
    """Try connecting to the protected port after knocking."""
    # TODO: Replace with real service connection if needed.
    print(f"CHECKING CONNECTION FOR {target}:{protected_port}")

    try:
        # USE TCP TO ACTUALLY ATTEMPT TO CONNECT TO THE PROTECTED PORT WITH SSH

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        res = sock.connect_ex((target, protected_port))
        sock.close()

        if res == 0:
            print(f"SUCCESS PORT {protected_port} IS OPEN")
            return True
        else:
            print(f"FAILURE PORT {protected_port} is INACCESSIBLE (ERR: {res})")
    except OSError as e:
        print(f"[-] Could not connect to protected port {protected_port} (err: {e})")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking client starter")
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt connection to protected port after knocking",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        check_protected_port(args.target, args.protected_port)


if __name__ == "__main__":
    main()
