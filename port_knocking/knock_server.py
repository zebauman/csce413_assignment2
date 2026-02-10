#!/usr/bin/env python3
"""port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
import threading
import select

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
OPEN_DURATION = 10  # CONFIG THE AMOUNT OF TIME TO KEEP THE PORT OPEN -> TIMEOUT


# TRACK THE CLIENTS' STATES WHERE {'ip addr': {'stage': 0, 'last knock': timestamp}}
client_states = {}

# FIREWALL RULES TO MAKE SURE THAT THE PROTECTED PORT IS CLOSED BY DEFAULT - FAIL-SECURE DEFAULT
def setup_firewall_rules(protected_port):

    # CHECK THE IP TABLES TO CHECK IF THE DROP RULE ALREADY EXISTS -> ADD IFF DOESN'T EXIST
    ret = subprocess.run(
        ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"],
        stderr = subprocess.DEVNULL
    )
    if ret.returncode != 0:
        logging.info(f"Adding default DROP rule for port {protected_port}")
        # ADD THE DROP RULE FOR THE PORT
        subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"], check=True)

# LOGS THE SERVER'S ACTIONS AND ISSUES TO THE SERVER ADMIN
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(client_ip, protected_port):
    """Open the protected port using firewall rules."""
    logging.info(f"AUTHENTICATED: OPENING PORT {protected_port} for {client_ip}")

    # USE THE IPTABLES TO ALLOW ACCESS TO THE AUTH. IP FOR THE PORT
    # INSERT IS USED TO PLACE THE ROLE (ALLOWING THE CLIENT IP) ON THE TOP OF THE HIERACHY OF RULES, BYPASSING THE DROP ROLE FOR THE AUTH. USER
    # ONLY THE AUTH. IP ADDRESS IS GRANTED ACCESS
    cmd = ["iptables", "-I", "INPUT", "-s", client_ip, "-p", "tcp", "--dport", str(protected_port), "-j", "ACCEPT"]
    subprocess.run(cmd, check=True)

    # AUTOMATICALLY CLOSE THE AUTH. AFTER 10 SECONDS SO AFTER 10 SECONDS -> REMOVES THE RULE AFTER 10 SECONDS, if user disconnects from connection then will have to reauth.
    t = threading.Timer(OPEN_DURATION, close_protected_port, [client_ip, protected_port])
    t.start()


def close_protected_port(client_ip, protected_port):
    """Close the protected port using firewall rules."""

    logging.info(f"TIMEOUT: Closing port {protected_port} for {client_ip}")

    # REMOVE THE RULE FOR THE CLIENT IP THAT GRANTED ACCESS TO THE PROTECTED PORT

    cmd = ["iptables", "-D", "INPUT", "-s", client_ip, "-p", "tcp", "--dport", str(protected_port), "-j", "ACCEPT"]
    subprocess.run(cmd, check=False)    # IF CHECK IS TRUE THEN SERVER CRASHES SO MAKE FALSE

def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    # CONCURRENCY WITH SELECT() WHERE NON-BLOCKING SOCKETS ARE USED AND SELECT() IS USED TO MONITOR THEM ALL AT THE SAME TIME (CONCURRENCY)
    sockets = []
    socket_map = {}

    try:
        for port in sequence:
            # USE UDP BECAUSE IT'S CONNECTIONLESS AND WON'T TELL IF THE PORT PINGED IS CLOSED -> UDP WILL JUST DROP THE PACKET; NO ACKS
            s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))

            s.setblocking(False)
            sockets.append(s)
            socket_map[s] = port

            logger.info(f"Bound to UDP port {port}")
        
        setup_firewall_rules(protected_port)    # CONFIGURE THE FIREWALL FOR THE PROTECTED PORT

        while True:
            # SELECT WILL SLEEP UNTIL ONE OF THE SOCKETS RECEIEVES DATA 
            readable, _, _ = select.select(sockets, [], [])

            for s in readable:
                data, addr = s.recvfrom(1024)
                client_ip = addr[0]
                port_knocked = socket_map[s]

                now = time.time()

                state = client_states.get(client_ip, {"stage": 0, 'last_knock': 0})

                # IF THE USER TAKES TOO LONG BETWEEN THE KNOCKS -> RESET THEM
                if now - state['last_knock'] > window_seconds and state['stage'] > 0:
                    logger.debug(f"Timeout for {client_ip}. Resetting.")
                    state['stage'] = 0
                
                expected_port = sequence[state['stage']]

                if port_knocked == expected_port: # VERIFY THAT THE PORT KNOCKED MATCHES THE EXPECTED PORT FOR THE CURRENT STEP IN THE SEQUENCE
                    logger.info(f"Correct knock {state['stage']+1}/{len(sequence)} from {client_ip} on port {port_knocked}")
                    state['stage'] += 1
                    state['last_knock'] = now

                    if state['stage'] == len(sequence): # CHECK IF COMPLETE
                        open_protected_port(client_ip, protected_port)
                        state['stage'] = 0  # RESET THE STAGE TO RE-KNOCK TO LOGIN AGAIN LATER
                else:   # IF THE WRONG PORT IS KNOCKED THEN RESET THE PROGRESS
                    if state['stage'] > 0:
                        logger.info(f"Wrong knock from {client_ip} on {port_knocked}. Expected {expected_port}. Resetting.")
                    state['stage'] = 0
                
                # SAVE RESULT FOR THE CLIENT IP
                client_states[client_ip] = state


    except KeyboardInterrupt:
        logger.info("SERVER STOPPING")
    finally:
        for s in sockets:
            s.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
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
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
