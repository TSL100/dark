"""Modular DFIR artifact parser package.

Each parser converts a specific Windows artifact format into a
standardized JSON schema consumed by the DFIR Timeline Analyzer UI.
"""

from parsers.base import ArtifactEvent, BaseParser, SCHEMA_VERSION
from parsers.prefetch import PrefetchParser
from parsers.lnk import LNKParser
from parsers.jumplist import JumpListParser
from parsers.amcache import AmcacheParser
from parsers.userassist import UserAssistParser
from parsers.bam import BAMParser
from parsers.shellbag import ShellbagParser
from parsers.recyclebin import RecycleBinParser
from parsers.recentdocs import RecentDocsParser
from parsers.shimcache import ShimCacheParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "prefetch": PrefetchParser,
    "lnk": LNKParser,
    "jumplist": JumpListParser,
    "amcache": AmcacheParser,
    "userassist": UserAssistParser,
    "bam": BAMParser,
    "shellbag": ShellbagParser,
    "recyclebin": RecycleBinParser,
    "recentdocs": RecentDocsParser,
    "shimcache": ShimCacheParser,
}

__all__ = [
    "ArtifactEvent",
    "BaseParser",
    "SCHEMA_VERSION",
    "PARSER_REGISTRY",
    "PrefetchParser",
    "LNKParser",
    "JumpListParser",
    "AmcacheParser",
    "UserAssistParser",
    "BAMParser",
    "ShellbagParser",
    "RecycleBinParser",
    "RecentDocsParser",
    "ShimCacheParser",
]
