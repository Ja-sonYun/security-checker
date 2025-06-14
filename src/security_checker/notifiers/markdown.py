from security_checker.checkers._models import CheckResultInterface
from security_checker.console import console
from security_checker.notifiers._base import NotifierBase


class MarkdownNotifier(NotifierBase):
    async def send_notification(self, result: CheckResultInterface) -> bool:
        markdown_text = f"# {result.checker_name} Results\n\n"

        for detail in result.get_details():
            markdown_text += f"{detail}\n"

        filename = result.checker_name.replace(" ", "_").lower() + "_results.md"

        console.verbose(f"Writing results to markdown file '{filename}'...")
        with open(filename, "w") as file:
            file.write(markdown_text)

        return True
