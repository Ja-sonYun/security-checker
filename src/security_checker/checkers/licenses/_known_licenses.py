import re
from typing import Literal

_LICENSE_SCORE: dict[Literal[1, 2, 3], tuple[str, ...]] = {
    3: (  # Strong copyleft
        # GPL family
        "affero gpl",
        "agpl",
        "gpl-3",
        "gpl v3",
        "gpl3",
        "gpl-2",
        "gpl v2",
        "gpl2",
        # Alternative strong copyleft licenses
        "sspl",
        "server side public license",
        "osl-3",
        "open software license",
        "sugarcrm public license",
        "dsl license",
        "design science license",
        "cockroach community",
        "cal-1",
        "commons clause",
    ),
    2: (  # Weak / file-level copyleft
        "lgpl",
        "lesser gpl",
        "mozilla public license",
        "mpl",
        "eclipse public license",
        "epl",
        "cddl",
        "common development and distribution",
        "cecill",
        "cpal",
        "sleepycat license",  # db-specific copyleft
    ),
    1: (  # Permissive / public-domain–like
        "apache license",
        "apache-2",
        "apache 1.1",
        "bsd 3",
        "bsd-3",
        "bsd 2",
        "bsd-2",
        "bsd-4",
        "bsd license",
        "mit license",
        "mit-0",
        "mit",
        "x11",
        "historical permission notice",
        "isc",
        "zlib",
        "libpng",
        "openssl",
        "boost software license",
        "bsl-1",
        "bsl-1.0",
        "artistic license 2",
        "postgresql",
        "psf",
        "hpnd",
        "public domain",
        "unlicense",
        "cc0",
        "wtfpl",
    ),
}


def _normalize_license_name(name: str) -> str:
    return name.lower().replace(" ", "").replace("-", " ").replace("_", " ").strip()


_KEYWORD_TO_SCORE: dict[str, Literal[1, 2, 3]] = {
    _normalize_license_name(kw): score
    for score, kws in _LICENSE_SCORE.items()
    for kw in kws
}


def detect_license_score(raw: str) -> Literal[0, 1, 2, 3]:
    text = _normalize_license_name(raw)
    for kw, score in _KEYWORD_TO_SCORE.items():
        if kw in text:
            return score
    return 0  # Unknown license score
