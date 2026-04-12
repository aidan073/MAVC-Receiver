from .message.command import Command

import socket
import threading
from queue import Queue
from dataclasses import dataclass

from typing import Callable, Dict, List


class Receiver:
    _cfg: ReceiverCfg
    _queue: Queue[Command]
    _parser: Callable
    _server: socket.socket
    _client_sockets: List[socket.socket]
    _client_threads: List[threading.Thread]
    _spin_callbacks: List[Callable]
    _instant_callbacks: List[Callable]

    _started = False

    def __init__(self, cfg: ReceiverCfg = None):
        if not cfg:
            cfg = ReceiverCfg()
        pass

    def run(self) -> None:
        try:
            if self._started:
                raise ValueError(
                    "Receiver server has already been started, ensure it has been stopped before calling Receiver.run() again."
                )
            self._started = True
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.bind((self._cfg.bind_host, self._cfg.bind_port))
            self._server.listen(self._cfg.max_connections)
            server_conn_thread = threading.Thread(target=self._server_conn_loop)
            server_conn_thread.start()

        except Exception as e:
            print(f"[MAVC-Receiver] Server had an error while running: {e}")
            # TODO: Close server connection here, set _started to False

    def stop(self) -> bool:
        # close all connections, maybe destroy threads (will this break something?), close server, clear references
        self._started = False
        pass

    def spin_once(self) -> None:
        # call all spin callbacks
        # acquire lock on queue here? So all callbacks receive the same queue state?
        pass

    def poll(self, remove_message: bool = True) -> Dict:
        return {}

    # === Callbacks ===
    def register_callback(
        self, callback_fn: Callable, execute_on_spin: bool = True
    ) -> bool:
        try:
            if (
                callback_fn in self._spin_callbacks
                or callback_fn in self._instant_callbacks
            ):
                raise ValueError(
                    "The provided callback function is already registered and cannot be registered again."
                )
            if execute_on_spin:
                self._spin_callbacks.append(callback_fn)
            else:
                self._instant_callbacks.append(callback_fn)
        except Exception as e:
            print(f"[MAVC-Receiver] Error registering callback: {e}")
            return False
        return True

    def unregister_callback(self, callback_fn: Callable) -> bool:
        try:
            if callback_fn in self._spin_callbacks:
                self._spin_callbacks.remove(callback_fn)
            elif callback_fn in self._instant_callbacks:
                self._instant_callbacks.remove(callback_fn)
            else:
                raise ValueError(
                    f"The provided callback does not match any registered callback."
                )
        except Exception as e:
            print(f"[MAVC-Receiver] Error unregistering callback: {e}")
            return False
        return True

    def count_callbacks(self) -> int:
        return len(self._instant_callbacks) + len(self._spin_callbacks)

    # === Parsing ===
    def set_parser(self, parse_fn: Callable) -> None:
        self._parser = parse_fn

    # === Private Methods ===
    def _server_conn_loop(self) -> None:
        while True:
            client, _ = self._server.accept()
            self._client_sockets.append(client)
            client_conn_thread = threading.Thread(target=self._rec_loop, args=(client))
            self._client_threads.append(client_conn_thread)
            client_conn_thread.start()

    def _rec_loop(self, client: socket.socket) -> None:
        while True:
            data = client.recv(self._cfg.buffer_size)


@dataclass
class ReceiverCfg:
    message_size: int = 128  # TODO: Match this to default message size
    buffer_size: int = 1024
    bind_host: str = "0.0.0.0"
    bind_port: int = 5073
    max_connections: int = 1


@dataclass
class CallbackCfg:
    execute_on_spin: bool = True
