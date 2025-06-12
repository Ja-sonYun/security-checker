from abc import ABC, abstractmethod

from security_checker.checkers._models import CheckResultInterface


class NotifierBase(ABC):
    @abstractmethod
    async def send_notification(self, result: CheckResultInterface) -> bool: ...
