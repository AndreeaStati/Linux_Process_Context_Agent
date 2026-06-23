from abc import ABC, abstractmethod
from typing import Any, Dict


class OutputDispatcher(ABC):

    def start(self) -> None:
        return None

    @abstractmethod
    def emit(self, ecs_doc: Dict[str, Any]) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        return None
