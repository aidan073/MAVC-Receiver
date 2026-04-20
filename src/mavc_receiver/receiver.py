from .wire.command import Command
from .cfg_parser import ReceiverCfg, load_cfg
from .wire.command_parser import CommandParser

import socket
import threading
from pathlib import Path
from queue import Queue, Empty
from typing import Callable, List, Optional, Tuple


class Receiver:
    _JOIN_TIMEOUT_S = 5.0

    _cfg: ReceiverCfg
    _queue: Queue[Command]
    _parser: Callable
    _server: Optional[socket.socket]
    _server_thread: Optional[threading.Thread]
    _client_sockets: List[socket.socket]
    _client_threads: List[threading.Thread]
    _spin_callbacks: List[Callable]
    _instant_callbacks: List[Tuple[Callable, bool]]

    _started: bool

    def __init__(
        self,
        cfg: ReceiverCfg | Path | str | None = None,
    ) -> None:
        if cfg is None:
            self._cfg = ReceiverCfg()
        elif isinstance(cfg, ReceiverCfg):
            self._cfg = cfg
        elif isinstance(cfg, (str, Path)):
            self._cfg = load_cfg(Path(cfg))
        else:
            raise TypeError(
                "[MAVC-Receiver] Cfg must be None, a ReceiverCfg, or a path to a .yaml file"
            )

        self._queue: Queue[Command] = Queue()
        self._client_sockets: List[socket.socket] = []
        self._client_threads: List[threading.Thread] = []
        self._spin_callbacks: List[Callable] = []
        self._instant_callbacks: List[Tuple[Callable, bool]] = []
        self._command_parser = CommandParser()
        self._server = None
        self._server_thread = None
        self._started = False

    def run(self) -> None:
        """
        Bind a TCP listen socket and start the accept loop on a background thread.
        """
        if self._started:
            print(
                "[MAVC-Receiver] Receiver server has already been started, ensure it has been stopped before calling Receiver.run() again."
            )
            return
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.bind((self._cfg.bind_host, self._cfg.bind_port))
            self._server.listen(self._cfg.max_connections)
            self._started = True
            self._server_thread = threading.Thread(
                target=self._server_conn_loop,
                name="mavc-receiver-accept",
                daemon=False,
            )
            self._server_thread.start()

        except Exception as e:
            print(f"[MAVC-Receiver] Server had an error while running: {e}")
            self._started = False
            self._server_thread = None
            if self._server is not None:
                try:
                    self._server.close()
                except OSError:
                    pass
                self._server = None

    def stop(self) -> bool:
        """
        Stop accepting connections, close all sockets, and wait for worker threads.

        Closes the listening socket first so the accept loop exits, then shuts down
        each client socket so receive loops end, then joins threads (within
        :attr:`_JOIN_TIMEOUT_S` each). Safe to call more than once.

        Note: Do not call from an instant callback on the receive thread; joining that thread from itself can deadlock.

        Returns:
            True if shutdown completed without unexpected errors and every thread joined
            within the timeout. False if any step failed, a join timed out, or a
            non-OS error was caught.
        """
        self._started = False
        ok = True
        try:
            if self._server is not None:
                try:
                    self._server.close()
                except OSError:
                    ok = False
                finally:
                    self._server = None

            for client in list(self._client_sockets):
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    client.close()
                except OSError:
                    ok = False

            if self._server_thread is not None:
                self._server_thread.join(timeout=self._JOIN_TIMEOUT_S)
                if self._server_thread.is_alive():
                    ok = False
                self._server_thread = None

            for t in list(self._client_threads):
                t.join(timeout=self._JOIN_TIMEOUT_S)
                if t.is_alive():
                    ok = False
            self._client_threads.clear()
            self._client_sockets.clear()

        except Exception as e:
            print(
                f"[MAVC-Receiver] Error during stop (shutdown may be incomplete): {e}"
            )
            return False

        return ok

    def spin_once(self) -> bool:
        """
        Non-blocking: if the queue is non-empty, dequeue one ``Command`` and call each spin
        callback as ``callback(self, command)``. If the queue is empty, callbacks are not
        invoked.

        Note: Callbacks run on the same thread that calls ``spin_once``.

        Returns:
            True if callbacks were invoked, False if the queue was empty.
        """
        try:
            command = self._queue.get_nowait()
        except Empty:
            return False
        for callback in self._spin_callbacks:
            try:
                callback(self, command)
            except Exception as e:
                print(f"[MAVC-Receiver] Error in spin callback: {e}")
        return True

    def poll(self) -> Command | None:
        try:
            return self._queue.get_nowait()
        except Empty:
            return None

    # === Callbacks ===
    def register_callback(
        self,
        callback_fn: Callable,
        execute_on_spin: bool = True,
        digest: bool = False,
    ) -> bool:
        """
        Register a callback. Spin callbacks run from ``spin_once`` on the ``spin_once`` caller's thread.
        Instant callbacks run in the receive thread as soon as a command is decoded.

        Args:
            callback_fn (Callable): A callable with the form ``callback(self, command: Command)``.
            execute_on_spin (bool): If True, register a spin callback; if False, an instant callback.
                Spin callbacks only run when ``spin_once`` is called and a command was available. Instant
                callbacks run whenever a command is received on the receive thread.
            digest (bool): Applies to instant callbacks only. If True, after instant callbacks run when a command is received,
                the command is not enqueued and thus spin_once and poll will not receive it.
        """
        try:
            instant_ids = {fn for fn, _ in self._instant_callbacks}
            if callback_fn in self._spin_callbacks or callback_fn in instant_ids:
                raise ValueError(
                    "The provided callback function is already registered and cannot be registered again."
                )
            if execute_on_spin:
                self._spin_callbacks.append(callback_fn)
            else:
                self._instant_callbacks.append((callback_fn, digest))
        except Exception as e:
            print(f"[MAVC-Receiver] Error registering callback: {e}")
            return False
        return True

    def unregister_callback(self, callback_fn: Callable) -> bool:
        """
        Remove ``callback_fn`` from either the spin or instant callback list.

        Matches the same function object passed to :meth:`register_callback`.

        Returns:
            True if removed, False if an error occurred or the callback was unknown.
        """
        try:
            if callback_fn in self._spin_callbacks:
                self._spin_callbacks.remove(callback_fn)
            else:
                for i, (fn, _) in enumerate(self._instant_callbacks):
                    if fn is callback_fn:
                        del self._instant_callbacks[i]
                        break
                else:
                    raise ValueError(
                        "The provided callback does not match any registered callback."
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
        """Do not call externally. Block on :meth:`socket.accept`, track each client, and start :meth:`_rec_loop` per connection."""
        assert self._server is not None
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:
                break
            self._client_sockets.append(client)
            client_conn_thread = threading.Thread(
                target=self._rec_loop,
                args=(client,),
                name="mavc-receiver-client",
                daemon=False,
            )
            self._client_threads.append(client_conn_thread)
            client_conn_thread.start()

    def _rec_loop(self, client: socket.socket) -> None:
        """
        Do not call externally. Receive bytes from ``client``, parse fixed-size ``Command`` frames, run instant handlers, then enqueue.

        Buffers partial reads until ``frame_size`` bytes are available. If decoding fails
        (checksum, magic, etc.), discards one byte and retries to resync the stream.
        When the peer closes the connection, closes the socket and drops it from
        :attr:`_client_sockets`.
        """
        frame_size = self._command_parser._decoder_struct.size
        buf = bytearray()
        try:
            while self._started:
                data = client.recv(self._cfg.buffer_size)
                if not data:
                    break
                buf.extend(data)
                while len(buf) >= frame_size:
                    chunk = bytes(buf[:frame_size])
                    try:
                        cmd = self._command_parser.decode(chunk)
                        skip_queue = False
                        for instant_cb, digest in list(self._instant_callbacks):
                            try:
                                instant_cb(self, cmd)
                            except Exception as e:
                                print(f"[MAVC-Receiver] Error in instant callback: {e}")
                            if digest:
                                skip_queue = True
                        if not skip_queue:
                            self._queue.put(cmd)
                    except ValueError as e:
                        del buf[0]
                        print(f"[MAVC-Receiver] Error decoding a chunk, retrying: {e}")
                        continue
                    del buf[:frame_size]
        except Exception as e:
            print(f"[MAVC-Receiver] Error while receiving byte stream: {e}")
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass
            if client in self._client_sockets:
                self._client_sockets.remove(client)
