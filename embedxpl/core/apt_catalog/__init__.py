"""APT Group Attack Catalog: maps real-world threat actors to EmbedXPL modules.

Provides a structured catalog of Advanced Persistent Threat (APT) groups
that target network devices (routers, switches, IoT) covered by EmbedXPL.
Users can browse groups, review attack chains, and selectively reproduce
specific TTPs for security testing.

Version: 1.0.0
"""
from ._models import APTAttack, APTGroup, APT_CATALOG  # noqa: F401
from ._api import (  # noqa: F401
    get_catalog,
    get_group,
    list_groups,
    find_groups_by_device,
    find_groups_by_cve,
)
