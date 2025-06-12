from abc import ABC, abstractmethod
from collections.abc import Sequence

from pydantic import BaseModel


class CheckResultInterface(ABC):
    @abstractmethod
    def get_summary(self) -> str: ...

    @abstractmethod
    def get_details(self) -> Sequence[str]: ...

    @abstractmethod
    async def llm_summary(self) -> str: ...


class CheckResultBase(CheckResultInterface, BaseModel): ...
