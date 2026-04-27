"""
Minimal raw TCP listener (no mTLS) using Receiver.

Run from the repo root after installing the package, e.g.:
  pip install -e .
  python examples/raw_tcp_server.py

Connect a MAVC-Sender (or any client) to the printed host:port over plain TCP.
"""
from mavc_receiver import Receiver
from mavc_receiver.wire.command import Command
from mavc_receiver.cfg_parser import ReceiverCfg

import time
import signal


def main() -> None:
    cfg = ReceiverCfg(bind_port=9000)
    rx = Receiver(cfg)

    def on_command(_receiver: Receiver, cmd: Command) -> None:
        print(f"[MAVC-Example] {cmd!r}")

    rx.register_callback(on_command, execute_on_spin=True)
    rx.run()

    print(f"Listening on {rx._cfg.bind_host}:{rx._cfg.bind_port} (plain TCP, no TLS). " "Ctrl+C to stop.")

    stop = False
    def handle_stop(_signum: int, _frame: object | None) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    try:
        while not stop:
            rx.spin_once()
            time.sleep(0.005)
    finally:
        rx.stop()


if __name__ == "__main__":
    main()
