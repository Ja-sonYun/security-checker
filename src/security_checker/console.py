import warnings
from typing import Any

from rich.console import Console as _Console


class Console(_Console):
    def __init__(self) -> None:
        super().__init__()
        self._verbose = False

    def warning(self, *message: Any) -> None:
        formatted_message = " ".join(str(m) for m in message)
        warnings.warn(formatted_message, UserWarning, stacklevel=2)
        super().print(f"[yellow]Warning:[/yellow] {formatted_message}", highlight=False)

    def error(self, *message: Any) -> None:
        super().print(f"[red]Error:[/red] {' '.join(message)}", highlight=False)

    def verbose(self, *message: Any) -> None:
        if self._verbose:
            super().print(f"[blue]Debug:[/blue] {' '.join(message)}", highlight=False)

    def enable_verbose(self) -> None:
        self._verbose = True
        self.verbose("Verbose mode enabled.")


console = Console()
