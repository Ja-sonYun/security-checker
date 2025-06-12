from security_checker.checkers._models import CheckResultInterface
from security_checker.console import console
from security_checker.notifiers._base import NotifierBase


class StdoutNotifier(NotifierBase):
    async def send_notification(self, result: CheckResultInterface) -> bool:
        console.verbose("Generating summary for result with llm...")
        llm_summary = await result.llm_summary()
        console.print(llm_summary)
        return True
