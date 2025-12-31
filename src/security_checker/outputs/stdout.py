from security_checker.checkers._models import CheckResultInterface
from security_checker.console import console
from security_checker.outputs._base import OutputBase


class StdoutOutput(OutputBase):
    async def write_output(self, result: CheckResultInterface) -> bool:
        console.verbose("Preparing result output...")
        console.print(result.get_summary())
        for detail in result.get_details():
            console.print(detail)
        return True
