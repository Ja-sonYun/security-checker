import re

CODEBLOCK_RE = re.compile(
    r"""
    ^\s*```        # Start backtick
    (?:\w+)?\s*\n  # Language (optional)
    (.*?)          # Content
    \n?```.*$      # End backtick
    """,
    re.DOTALL | re.VERBOSE,
)


def strip_codeblock(text: str) -> str:
    m = CODEBLOCK_RE.match(text)
    return m.group(1) if m else text.strip()
