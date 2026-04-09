from .message import Message

from queue import Queue
from dataclasses import dataclass

from typing import Callable, Dict, List


class Receiver:
    _queue: Queue[Message]
    _parser: Callable
    _spin_callbacks: List[Callable]
    _instant_callbacks: List[Callable]

    def __init__(self):
        pass

    def spin_once(self) -> None:
        # call all spin callbacks
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
                    "[MAVC-Receiver] The provided callback function is already registered and cannot be registered again."
                )
            if execute_on_spin:
                self._spin_callbacks.append(callback_fn)
            else:
                self._instant_callbacks.append(callback_fn)
        except Exception as e:
            print(f"[MAVC-Receiver] Error registering callback: {e}")
        return True

    def unregister_callback(self, callback_fn: Callable) -> bool:
        try:
            if callback_fn in self._spin_callbacks:
                self._spin_callbacks.remove(callback_fn)
            elif callback_fn in self._instant_callbacks:
                self._instant_callbacks.remove(callback_fn)
            else:
                print(
                    f"[MAVC-Receiver] The provided callback does not match any registered callback. No callback was unregistered."
                )
        except Exception as e:
            print(f"[MAVC-Receiver] Error unregistering callback: {e}")

    def count_callbacks(self) -> int:
        return len(self._instant_callbacks) + len(self._spin_callbacks)

    # === Parsing ===
    def set_parser(self, parse_fn: Callable) -> None:
        self._parser = parse_fn


@dataclass
class CallbackCfg:
    execute_on_spin: bool = True
