"""The SaaS adapters, keyed by their kind (the name `DISCOVER` and the run summary use).

Each is the core's `Adapter` (`sensitive_data_core.adapter`), given a SaaS
`Context` (`sources/base.py`).
"""

from __future__ import annotations

from sensitive_data_core.adapter import Adapter

from .base import Context
from .gws_drive import DriveAdapter, SharedDriveAdapter
from .gws_gmail import GmailAdapter
from .m365_files import OneDriveAdapter, SharePointAdapter
from .m365_mail import MailAdapter
from .m365_teams import ChannelsAdapter, ChatsAdapter

_ALL: list[Adapter[Context]] = [
    MailAdapter(),
    OneDriveAdapter(),
    SharePointAdapter(),
    ChannelsAdapter(),
    ChatsAdapter(),
    GmailAdapter(),
    DriveAdapter(),
    SharedDriveAdapter(),
]
ADAPTERS: dict[str, Adapter[Context]] = {a.kind: a for a in _ALL}
