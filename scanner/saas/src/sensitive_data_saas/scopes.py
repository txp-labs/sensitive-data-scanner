"""Every permission and scope the SaaS scanner asks a vendor for, in one place.

Each adapter takes the scopes it requests from here, and docs/SAAS.md lists
the same. A strict test holds every one to a per-vendor list of scopes that
only read (`tests/test_saas_scopes.py`, with the release).

- **Microsoft 365**: Graph application permissions, consented by an admin.
  An app token carries exactly what was consented (`.default`); these are the
  ones the scanner's calls need.
- **Google Workspace**: OAuth scopes the Admin console's domain-wide
  delegation grants the service account's client id, and the scanner requests
  per user.
"""

from __future__ import annotations

# Microsoft Graph application permissions, by what needs them.
M365_PEOPLE = ("User.Read.All",)
M365_GROUPS = ("GroupMember.Read.All",)
M365_MAIL = ("Mail.Read",)
M365_FILES = ("Files.Read.All",)
M365_SITES_SELECTED = ("Sites.Selected",)
M365_SITES_ALL = ("Sites.Read.All",)
M365_TEAMS_CHANNELS = ("Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All")
M365_TEAMS_CHATS = ("Chat.Read.All",)

# Google Workspace OAuth scopes (domain-wide delegation).
GWS_DIRECTORY = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
)
GWS_GMAIL = ("https://www.googleapis.com/auth/gmail.readonly",)
GWS_DRIVE = ("https://www.googleapis.com/auth/drive.readonly",)

REQUESTED: dict[str, tuple[str, ...]] = {
    "m365": (
        *M365_PEOPLE,
        *M365_GROUPS,
        *M365_MAIL,
        *M365_FILES,
        *M365_SITES_SELECTED,
        *M365_SITES_ALL,
        *M365_TEAMS_CHANNELS,
        *M365_TEAMS_CHATS,
    ),
    "google_workspace": (*GWS_DIRECTORY, *GWS_GMAIL, *GWS_DRIVE),
}
