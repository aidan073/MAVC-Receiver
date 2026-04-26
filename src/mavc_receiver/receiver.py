from .wire.command import Command
from .wire.command_parser import CommandParser
from .cfg_parser import ReceiverCfg, load_cfg, validate_receiver_mtls_cfg

import ssl
import socket
import threading
from pathlib import Path
from queue import Queue, Empty
from colorama import Fore, Style, init as colorama_init

from typing import Callable, List, Optional, Tuple

colorama_init()


def _log_warn(msg: str) -> None:
    print(f"{Fore.YELLOW}{msg}{Style.RESET_ALL}")


def _log_error(msg: str) -> None:
    print(f"{Fore.RED}{msg}{Style.RESET_ALL}")


class Receiver:
    _JOIN_TIMEOUT_S = 5.0

    _cfg: ReceiverCfg
    _queue: Queue[Command]
    _parser: Callable
    _server: Optional[socket.socket]
    _server_thread: Optional[threading.Thread]
    _mtls_ctx: Optional[ssl.SSLContext]
    _client_sockets: List[socket.socket]
    _client_threads: List[threading.Thread]
    _spin_callbacks: List[Callable]
    _instant_callbacks: List[Tuple[Callable, bool]]
    _clients_lock: threading.Lock
    _callbacks_lock: threading.Lock

    _started: bool

    def __init__(
        self,
        cfg: ReceiverCfg | Path | str | None = None,
    ) -> None:
        self.is_safe = False
        if cfg is None:
            self._cfg = ReceiverCfg()
            self.is_safe = True
        elif isinstance(cfg, ReceiverCfg):
            self._cfg = cfg
            self.is_safe = True
        elif isinstance(cfg, (str, Path)):
            try:
                self._cfg = load_cfg(Path(cfg))
                self.is_safe = True
            except Exception as e:
                _log_error(
                    f"[MAVC-Receiver] Failed to load config from {cfg!r}: {e}. "
                    "Using default settings; this instance is unsafe until you fix the file or pass a ReceiverCfg."
                )
                self._cfg = ReceiverCfg()
                self.is_safe = False
        else:
            _log_error(
                "[MAVC-Receiver] Cfg must be None, a ReceiverCfg, or a path to a .yaml file. "
                "Using default settings; this instance is unsafe."
            )
            self.is_safe = False

        self._queue: Queue[Command] = Queue()
        self._client_sockets: List[socket.socket] = []
        self._client_threads: List[threading.Thread] = []
        self._spin_callbacks: List[Callable] = []
        self._instant_callbacks: List[Tuple[Callable, bool]] = []
        self._clients_lock = threading.Lock()
        self._callbacks_lock = threading.Lock()
        self._command_parser = CommandParser()
        self._server = None
        self._server_thread = None
        self._mtls_ctx = None
        self._started = False

    def run(self, ignore_safety: bool = False) -> None:
        """
        Bind a TCP listen socket and start the accept loop on a background thread.

        Args:
            ignore_safety (bool): If set to True, a configuration issue during intialization of Receiver won't block this method from running. Defaults to False.
        """
        if not self.is_safe:
            if not ignore_safety:
                _log_error(
                    "[MAVC-Receiver] Server launch cancelled: Receiver is in an unsafe state "
                    "(config load failed or invalid cfg type) and ignore_safety is False."
                )
                return
            _log_warn(
                "[MAVC-Receiver] Receiver is unsafe (config load failed or invalid cfg type), "
                "but ignore_safety is True; starting the server anyway."
            )

        if self._started:
            _log_warn("[MAVC-Receiver] Server is already running; stop it before calling run() again.")
            return
        try:
            validate_receiver_mtls_cfg(self._cfg)
            if self._cfg.verify_client_identity:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(
                    certfile=self._cfg.server_cert_path,
                    keyfile=self._cfg.server_key_path,
                )
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile=self._cfg.ca_cert_path)
                self._mtls_ctx = ctx
            else:
                self._mtls_ctx = None

            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.settimeout(1.0)  # Necessary so `while _started` condition gets checked repeatedly
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
            _log_error(f"[MAVC-Receiver] Server failed to start: {e}")
            self._started = False
            self._server_thread = None
            self._mtls_ctx = None
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
            server_to_close: Optional[socket.socket] = self._server
            if self._server is not None:
                try:
                    server_to_close.close()
                except OSError:
                    ok = False

            if self._server_thread is not None:
                self._server_thread.join(timeout=self._JOIN_TIMEOUT_S)
                if self._server_thread.is_alive():
                    ok = False
            self._server_thread = None
            self._server = None

            self._mtls_ctx = None

            with self._clients_lock:
                clients = list(self._client_sockets)
                client_threads = list(self._client_threads)

            for client in clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    client.close()
                except OSError:
                    ok = False

            for t in client_threads:
                if t is threading.current_thread():
                    continue
                t.join(timeout=self._JOIN_TIMEOUT_S)
                if t.is_alive():
                    ok = False
            with self._clients_lock:
                self._client_threads.clear()
                self._client_sockets.clear()

        except Exception as e:
            _log_error(f"[MAVC-Receiver] Error during stop (shutdown may be incomplete): {e}")
            return False

        return ok

    def spin_once(self) -> bool:
        """
        Non-blocking: if the queue is non-empty, dequeue one ``Command`` and call each spin
        callback as ``callback(self, command)``. If the queue is empty, callbacks are not
        invoked.

        Note: Callbacks run on the same thread that calls ``spin_once``.

        Returns:
            True if callbacks were invoked, False if the receiver is stopped or
            the queue was empty.
        """
        if not self._started:
            return False
        try:
            command = self._queue.get_nowait()
        except Empty:
            return False
        with self._callbacks_lock:
            spin_callbacks = list(self._spin_callbacks)
        for callback in spin_callbacks:
            try:
                callback(self, command)
            except Exception as e:
                _log_error(f"[MAVC-Receiver] Error in spin callback: {e}")
        return True

    def poll(self) -> Command | None:
        if not self._started:
            return None
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
            with self._callbacks_lock:
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
            _log_error(f"[MAVC-Receiver] Error registering callback: {e}")
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
            with self._callbacks_lock:
                if callback_fn in self._spin_callbacks:
                    self._spin_callbacks.remove(callback_fn)
                else:
                    for i, (fn, _) in enumerate(self._instant_callbacks):
                        if fn is callback_fn:
                            del self._instant_callbacks[i]
                            break
                    else:
                        raise ValueError("The provided callback does not match any registered callback.")
        except Exception as e:
            _log_error(f"[MAVC-Receiver] Error unregistering callback: {e}")
            return False
        return True

    def count_callbacks(self) -> int:
        with self._callbacks_lock:
            return len(self._instant_callbacks) + len(self._spin_callbacks)

    # === Parsing ===
    def set_parser(self, parse_fn: Callable) -> None:
        self._parser = parse_fn

    # === Private Methods ===
    def _server_conn_loop(self) -> None:
        """Do not call externally. Block on :meth:`socket.accept`, track each client, and start :meth:`_rec_loop` per connection."""
        while self._started:
            try:
                server = self._server
                if server is None:
                    break
                client, _ = server.accept()
                client.settimeout(1.0)
            except socket.timeout:
                continue
            except OSError:
                break
            if self._mtls_ctx is not None:
                try:
                    client = self._mtls_ctx.wrap_socket(client, server_side=True)
                except ssl.SSLError as e:
                    _log_error(f"[MAVC-Receiver] mTLS handshake failed, closing client: {e}")
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
            with self._clients_lock:
                self._client_sockets.append(client)
                total_connections = len(self._client_sockets)
            print(f"[MAVC-Receiver] Received new client connection. Total connections is {total_connections}")
            client_conn_thread = threading.Thread(
                target=self._rec_loop,
                args=(client,),
                name="mavc-receiver-client",
                daemon=False,
            )
            with self._clients_lock:
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
                try:
                    data = client.recv(self._cfg.buffer_size)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf.extend(data)
                while len(buf) >= frame_size:
                    chunk = bytes(buf[:frame_size])
                    try:
                        cmd = self._command_parser.decode(chunk)
                        skip_queue = False
                        with self._callbacks_lock:
                            instant_callbacks = list(self._instant_callbacks)
                        for instant_cb, digest in instant_callbacks:
                            try:
                                instant_cb(self, cmd)
                            except Exception as e:
                                _log_error(f"[MAVC-Receiver] Error in instant callback: {e}")
                            if digest:
                                skip_queue = True
                        if not skip_queue:
                            self._queue.put(cmd)
                    except ValueError as e:
                        del buf[0]
                        _log_warn(f"[MAVC-Receiver] Decode error on chunk, dropped 1 byte and resyncing: {e}")
                        continue
                    del buf[:frame_size]
        except Exception as e:
            _log_error(f"[MAVC-Receiver] Error while receiving byte stream: {e}")
        finally:
            try:
                client.close()
            except OSError:
                pass
            with self._clients_lock:
                try:
                    self._client_sockets.remove(client)
                except ValueError:
                    pass
                try:
                    self._client_threads.remove(threading.current_thread())
                except ValueError:
                    pass
