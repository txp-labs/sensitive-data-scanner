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
- **Slack**: the scopes of the customer's own Slack app (its manifest), which
  its token carries.
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
# #55, SCAN_MODE_M365 vendor or both: Purview DLP's alerts.
M365_ALERTS = ("SecurityAlert.Read.All",)

# Google Workspace OAuth scopes (domain-wide delegation).
GWS_DIRECTORY = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
)
GWS_GMAIL = ("https://www.googleapis.com/auth/gmail.readonly",)
GWS_DRIVE = ("https://www.googleapis.com/auth/drive.readonly",)
# #55, SCAN_MODE_GOOGLE_WORKSPACE vendor or both: the Alert Center's DLP alerts. Not
# read-only by its name (it can also change an alert's feedback or delete it): held to
# listing by the delegated administrator's role, Alert Center View only (docs/SAAS.md).
GWS_ALERTS = ("https://www.googleapis.com/auth/apps.alerts",)

# Slack: the app's bot token scopes, and the org-level Discovery API's (opt-in).
SLACK_CHANNELS = ("channels:read", "groups:read", "channels:history", "groups:history")
SLACK_FILES = ("files:read",)
SLACK_DISCOVERY = ("discovery:read",)
# #55, SCAN_MODE_SLACK vendor or both: the Audit Logs API's DLP events (an org token).
SLACK_AUDIT = ("auditlogs:read",)

# Atlassian OAuth 2.0 (3LO) classic scopes (an API token has none: it reads what its
# read-only service account may browse).
ATLASSIAN_JIRA = ("read:jira-work",)
ATLASSIAN_CONFLUENCE = (
    "read:confluence-content.all",
    "read:confluence-space.summary",
    "readonly:content.attachment:confluence",
)
ATLASSIAN_OFFLINE = ("offline_access",)

# The keyless signer's own federated token (Google's STS): IAM Credentials' signJwt only.
GOOGLE_SIGNER = ("https://www.googleapis.com/auth/iam",)

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
        *M365_ALERTS,
    ),
    "google_workspace": (*GWS_DIRECTORY, *GWS_GMAIL, *GWS_DRIVE, *GWS_ALERTS),
    "google_signer": GOOGLE_SIGNER,
    "slack": (*SLACK_CHANNELS, *SLACK_FILES, *SLACK_DISCOVERY, *SLACK_AUDIT),
    "atlassian": (*ATLASSIAN_JIRA, *ATLASSIAN_CONFLUENCE, *ATLASSIAN_OFFLINE),
}
