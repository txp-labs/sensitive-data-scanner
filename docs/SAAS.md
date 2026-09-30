# SaaS

The SaaS scanner runs **in your own environment**: a container you schedule on
ECS, Azure Container Apps, Cloud Run or Kubernetes, with **read-only** grants
to your SaaS tenants: Microsoft 365, Google Workspace and Slack. It samples mail, files and messages, and sends **findings
only, never values** ([FINDINGS.md](FINDINGS.md), schema 1.8). **Mermera's own
servers never read your SaaS content for this**: they receive findings, the
same as from the cloud scanners, so they stay out of what your content is in
scope for.

It is the same detection, findings contract, budgets, sampling, readers and
coverage summary as the cloud scanners (the cloud-neutral core,
`scanner/core`), in its own package (`scanner/saas`, `sensitive_data_saas`)
and its own image (`docker build --target saas`).

- **Read-only grants.** Each vendor's app holds only permissions that read.
  The scanner has no call that writes: nothing is marked read, moved, shared,
  labeled or changed.
- **No vendor SDK.** Every vendor is called over HTTPS with `requests`; tokens
  go only to the vendor's own API host.
- **Secrets stay out of the environment.** A certificate or a workload
  identity is preferred; a client secret is read from a file on a mounted
  secret volume, never an environment variable (the scanner refuses one), and
  never logged.
- **Only findings leave.** Site, library, team, channel, file and attachment
  names are masked like keys; **a person is named only by a hash** of their
  address (addresses are PII); the tenant by a hash of its id; each item by
  its vendor id, masked, and that id's hash.
- **Every tenant or store it cannot read is in the run summary with a
  reason**: `access_denied`, `scope_unverified` or `unscoped_grant` (mail),
  `protected_api` (Teams), `not_provisioned` (no mailbox or drive),
  `throttled` (the vendor kept asking to wait; the next run goes on),
  `not_a_member` (a Slack channel the app's bot was not invited to),
  `read_not_configured` (an opt-in kind not named in `DISCOVER`),
  `deferred` (the budget), `denied` or `not_allowed` (your rules).
- **Budgets and sampling**: the core's run budget (items, bytes, time) shared
  among the stores, a cap per mailbox, drive and channel per run, a stable
  sample by item id, and the vendors' rate limits honored (`Retry-After`).
- **Incremental**: delta queries (Microsoft Graph), Gmail's history and
  Drive's changes, with the cursors kept at
  `STATE_LOCATION`, so a run reads what changed since the last.

## Microsoft 365

| Kind (`DISCOVER`) | Store | Read with (Graph, application) | Default |
|---|---|---|---|
| `m365_mail` (`mail`, `exchange`) | A person's mailbox | `Mail.Read`, **scoped by Exchange** to the mailboxes in scope (below) | read, once the scope check passes |
| `m365_onedrive` (`onedrive`) | A person's OneDrive | `Files.Read.All` | read |
| `m365_sharepoint` (`sharepoint`) | A SharePoint site (its document libraries) | `Sites.Selected` with a `read` grant per site (preferred), or `Files.Read.All` | read |
| `m365_teams_channel` (`teams`, `channels`) | A team's channels | `Team.ReadBasic.All`, `Channel.ReadBasic.All`, `ChannelMessage.Read.All` (protected) | **off**: name it in `DISCOVER` |
| `m365_teams_chat` (`chats`) | A person's chats | `Chat.Read.All` (protected) | **off**: name it in `DISCOVER` |

And, for who is in scope: `User.Read.All` (to resolve `M365_USERS`) and
`GroupMember.Read.All` (only with `M365_GROUPS`). `Sites.Read.All` only for
`M365_SITES=all`. Every one of these reads.

### The people in scope

`M365_USERS` (principal names or object ids) and `M365_GROUPS` (group object
ids, expanded to their users, transitively) say whose mailboxes, OneDrives and
chats are read. Each is resolved to its object id once a run; every URL and
cursor uses the id, so no address is ever in a request path, a cursor or a
log. A person's store is named `user-<the first 16 hex of the SHA-256 of their
principal name, lower-case>`, and every finding and store carries the full
hash as `ownerHash`:

```sh
printf %s "alice@contoso.com" | tr '[:upper:]' '[:lower:]' | shasum -a 256
```

### Mail: scoped by Exchange, and proved scoped

Graph's `Mail.Read` as an application permission reads **every mailbox in the
tenant**. The scanner reads mail only when Exchange Online limits it to the
mailboxes you choose, and it checks that limit before it reads any.

**RBAC for Applications** (recommended). Do **not** consent to `Mail.Read` in
Entra for this app (an Entra grant is tenant-wide, and adds to any Exchange
scope). Give it the permission in Exchange, limited to a management scope, in
Exchange Online PowerShell:

```powershell
# The app's service principal in Exchange (the enterprise application's object id).
New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "Sensitive data scanner"

# The mailboxes in scope: here, the members of one group.
New-ManagementScope -Name "SDS scanned mailboxes" `
  -RecipientRestrictionFilter "MemberOfGroup -eq '<distinguished name of the group>'"

# Application Mail.Read, limited to that scope.
New-ManagementRoleAssignment -App <client-id> -Role "Application Mail.Read" `
  -CustomResourceScope "SDS scanned mailboxes"

# Check: True for a mailbox in scope, False for one outside it.
Test-ServicePrincipalAuthorization -Identity <client-id> -Resource <mailbox>
```

**An application access policy** (the older way): consent to `Mail.Read` in
Entra, then restrict the app to a mail-enabled security group:

```powershell
New-ApplicationAccessPolicy -AppId <client-id> -PolicyScopeGroupId <group address> `
  -AccessRight RestrictAccess -Description "Sensitive data scanner"
Test-ApplicationAccessPolicy -AppId <client-id> -Identity <mailbox>
```

**The scope check.** Set `M365_MAIL_SCOPE_CHECK` to a mailbox **outside** the
scope. Before reading any mail, the scanner asks Graph for one message id of
it:

| Answer | Then |
|---|---|
| Exchange refuses (`ErrorAccessDenied`) | the grant is scoped: mail in scope is read |
| A message is returned | every mailbox is `unscoped_grant`, and none is read |
| No setting, or any other answer (the mailbox does not exist) | every mailbox is `scope_unverified`, and none is read |

**What is read.** Each folder's messages, from a delta query
(`/users/{id}/mailFolders/{folder}/messages/delta`): the first run reads the
last `LOOKBACK_DAYS` (`receivedDateTime ge`), later runs only what changed. A
message's subject and body (as text) are read together; each file attachment
with the core's readers (Word, Excel and PowerPoint files, CSV, JSON, text,
Parquet, ORC and Avro by column). An attachment larger than `MAX_OBJECT_BYTES`
is counted as `too_large`; an attached item or a link to a cloud file as
`linked_item` (the file's own store reads it). A deleted message drops its
findings.

### SharePoint and OneDrive

**`Sites.Selected`** (preferred): the app reads only the sites an admin grants
it, one by one. Consent to `Sites.Selected` (application), then, as a
SharePoint admin, grant `read` on each site, for example with Graph (as an app
or admin that holds `Sites.FullControl.All`, used only for this step):

```http
POST https://graph.microsoft.com/v1.0/sites/{site-id}/permissions
{ "roles": ["read"],
  "grantedToIdentities": [{ "application": { "id": "<client-id>", "displayName": "Sensitive data scanner" } }] }
```

or with PnP PowerShell:
`Grant-PnPAzureADAppSitePermission -AppId <client-id> -DisplayName "Sensitive data scanner" -Site <site url> -Permissions Read`.
Name the sites in `M365_SITES` (`contoso.sharepoint.com:/sites/finance`, or a
site id).

**`Files.Read.All`** reads every OneDrive and every site; it is what reads the
OneDrives of the people in scope. **`Sites.Read.All`** lets `M365_SITES=all`
list every site.

**What is read.** Each document library (a site's store has one source per
library) and each OneDrive is read from its delta query
(`/drives/{id}/root/delta`): the first run lists every file, later runs only
what changed. A file is read with ranged GETs of its content (Graph redirects
to a pre-authenticated download URL; the app's token is not sent there), by
the core's readers. Media, PDFs, archives and the older binary Office formats
are counted by kind; a rights-managed (sensitivity-label encrypted) Office
file is `encrypted`. A deleted file drops its findings. At most
`FILES_MAX_PER_DRIVE` files a drive a run.

### Teams (opt-in)

Channel messages (`ChannelMessage.Read.All`) and chats (`Chat.Read.All`) are
**protected APIs**: Microsoft must approve the app for them
([the request form](https://aka.ms/teamsgraph/requestaccess)) before Graph
returns a message, whatever an admin consented to. Until then each team or
chat store is `protected_api`. Name the kinds in `DISCOVER` once approved.

- **Channels** (`m365_teams_channel`): the teams in `M365_TEAMS`. Each
  channel's messages come from a delta query, with each root message's
  replies. Bodies are HTML; their text is read. A file shared in a channel
  lives in the team's SharePoint site (that site's store reads it) and is
  counted here as `linked_item`.
- **Chats** (`m365_teams_chat`): the chats of the people in scope, each read
  newest first down to what the last complete read saw. A chat two people in
  scope share is read once a run.

At most `MESSAGES_MAX_PER_CHANNEL` messages per team, or per person's chats, a
run.

### Signing in

Register an app in your tenant (single tenant), consent to the permissions
above (application permissions; admin consent), and give the container **one**
credential:

| Credential | Setting | What |
|---|---|---|
| **A certificate** (preferred) | `M365_CERTIFICATE_FILE` | A PEM file with the private key and the certificate, on a mounted secret volume. Upload the certificate (public part) to the app. Each token request carries a client assertion signed with the key (`PS256`, `x5t#S256`), valid ten minutes. |
| **A federated workload identity** (preferred) | `M365_FEDERATED_TOKEN` | No secret at all: the app trusts a token the platform issues to the container, through a **federated identity credential** on the app (audience `api://AzureADTokenExchange`). The value says where the token comes from (below). |
| A client secret (the fallback) | `M365_CLIENT_SECRET_FILE` | A file on a mounted secret volume. `M365_CLIENT_SECRET` in the environment is refused. |

`M365_FEDERATED_TOKEN`:

| Value | Where the container runs | The federated credential on the app |
|---|---|---|
| `file:/var/run/secrets/tokens/entra` | Kubernetes (AKS workload identity's `AZURE_FEDERATED_TOKEN_FILE`, or any cluster's projected service account token with the audience) | issuer: the cluster's OIDC issuer; subject: `system:serviceaccount:<namespace>:<service account>` |
| `aws` | ECS or EKS: `sts:GetWebIdentityToken` as the task's or pod's role (IAM outbound identity federation, enabled for the account) | issuer: your account's outbound federation issuer URL; subject: the role's ARN |
| `gcp` | Cloud Run: the job's service account's identity token (metadata server) | issuer: `https://accounts.google.com`; subject: the service account's unique id |
| `azure` | Azure Container Apps (or any Azure compute) with a managed identity: its token for the audience; `M365_FEDERATED_CLIENT_ID` names a user-assigned identity | issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`; subject: the managed identity's object (principal) id |

The token is for `https://graph.microsoft.com/.default`, so it carries exactly
what was consented. It is kept in memory and renewed five minutes before it
expires; no credential, assertion or token is ever logged.

### Encryption at rest

Microsoft encrypts Microsoft 365 content at rest with its own keys
(`service_managed`). If your tenant uses **Microsoft Purview Customer Key**,
set `M365_CUSTOMER_KEY_ID` to your data encryption policy's id: findings then
say `customer_managed_key`, with `atRestKeyHash`, the SHA-256 of that id (the
id itself is never written). Graph does not report the policy, so the scanner
takes it from you.

## Google Workspace

| Kind (`DISCOVER`) | Store | Read with (domain-wide delegation) | Default |
|---|---|---|---|
| `gws_gmail` (`gmail`) | A person's mailbox | `https://www.googleapis.com/auth/gmail.readonly`, as that person | read |
| `gws_drive` (`drive`) | A person's My Drive (the files they own) | `https://www.googleapis.com/auth/drive.readonly`, as that person | read |
| `gws_shared_drive` (`shared_drive`) | A shared drive | `https://www.googleapis.com/auth/drive.readonly`, as `GWS_ADMIN_USER` (a member of the drive) | read |

And, for who is in scope, as `GWS_ADMIN_USER`:
`https://www.googleapis.com/auth/admin.directory.user.readonly` and
`https://www.googleapis.com/auth/admin.directory.group.member.readonly`.
Every one of these reads; no other scope is ever requested.

### Consent: domain-wide delegation, read-only scopes only

1. Make a service account in any Google Cloud project (no IAM role on
   anything; it needs none). Note its unique id (the OAuth client id).
2. In the Admin console, **Security > Access and data control > API controls
   > Domain-wide delegation > Add new**: the client id, and exactly these
   scopes, comma-separated:

   ```text
   https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly
   ```

3. `GWS_ADMIN_USER`: an administrator whose role can read users and groups
   (a custom admin role with *Users: Read* and *Groups: Read* is enough), and a
   member (Viewer) of each shared drive to read.

The scanner then acts as each person in scope, for those scopes: the JWT it
exchanges names the person (`sub`) and the scopes, and Google refuses any
scope the delegation does not list (`unauthorized_client`, the store's
`access_denied`).

### Who signs: keyless where possible

| `GWS_CREDENTIAL` | Where the container runs | Setup |
|---|---|---|
| `gcp` | Cloud Run, as a Google service account | Give the job's own service account **Service Account Token Creator** on the delegated service account (it may be the same one). Its metadata token calls IAM Credentials' `signJwt`; no key exists |
| `file:<path>`, `aws`, `azure` | Kubernetes, ECS or EKS, Azure Container Apps | **Workload identity federation**: a workload identity pool with a provider for the platform (OIDC: the cluster's issuer, AWS's outbound federation issuer, or Entra's issuer; default audience), and **Service Account Token Creator** on the delegated service account for the workload's principal. `GWS_WORKLOAD_PROVIDER` is the provider's resource name. The platform's token is exchanged at Google's STS; no key exists |
| (`GWS_KEY_FILE`) | anywhere (the fallback) | A service account key, a JSON file on a mounted secret volume, signs the JWT locally |

The signer needs only `iam.serviceAccounts.signJwt` on the delegated service
account. No key, JWT or token is ever logged.

### The people in scope

`GWS_USERS` (addresses), `GWS_GROUPS` (group addresses: their members, nested
groups included) and `GWS_ORG_UNITS` (organizational unit paths, `/Sales`),
listed with the Directory API; suspended users are left out. A person's
address is used only as the delegation's subject (inside a signed JWT): every
Gmail and Drive call is to `users/me`, so no address is in a URL, a cursor or
a log. A person's store is `user-<first 16 hex of ownerHash>`, as for
Microsoft 365.

### Gmail

The first run lists the last `LOOKBACK_DAYS` of messages (`newer_than:<n>d`,
spam and trash left out) and reads each: its subject and text parts together
(an HTML-only body as its text), and each attachment with the core's readers.
The mailbox's `historyId` at the start is kept; later runs read only the
messages added since (`users.history.list`), and a deleted message drops its
findings. A history too old for Gmail to keep starts a new pass. A person
without Gmail is `not_provisioned`. Nothing is labeled or marked read.
Gmail findings carry no link: Gmail has no link to another person's message.

### Drive

Each drive's files are listed once (`files.list`), after its change token is
taken; later runs read only what changed (`changes.list`), and a removed or
trashed file drops its findings. My Drive is the files a person owns (a file
shared with them is read in its owner's store). A file is read with ranged
`alt=media` GETs; a Google Docs, Sheets or Slides file is exported as text or
CSV (Drive caps an export at 10 MB). Forms, Drawings and other Google types
are counted as `document`, shortcuts as `linked_item`. A shared drive the
administrator is not a member of is `access_denied`.

Google encrypts Workspace data with its own keys (`service_managed`). A file
under Workspace client-side encryption is ciphertext to the API: it is not
read (counted by kind).

## Slack

| Kind (`DISCOVER`) | Store | Read with (the app's scopes) | Default |
|---|---|---|---|
| `slack_channel` (`slack`) | A public or private channel | `channels:read`, `groups:read` (to list), `channels:history`, `groups:history`, `files:read` | read, in the channels the app's bot is a member of |
| `slack_dm` (`dms`) | Direct and group messages, one store per organization | `discovery:read` (the Discovery API, Enterprise Grid only) | **off**: name it in `DISCOVER` |

### Consent: a Slack app of your own, read scopes only

Create an app from this manifest (**Your apps > Create New App > From an app
manifest**), install it to the workspace, and invite its bot to the channels
to scan (`/invite @Sensitive data scanner`). The scanner never joins a channel
itself: `channels:join` would be a write, and is not in the manifest.

```yaml
display_information:
  name: Sensitive data scanner
features:
  bot_user:
    display_name: Sensitive data scanner
oauth_config:
  scopes:
    bot:
      - channels:read
      - groups:read
      - channels:history
      - groups:history
      - files:read
settings:
  org_deploy_enabled: false
  socket_mode_enabled: false
```

Put the bot token (`xoxb-…`) in a file on a mounted secret volume and set
`SLACK_TOKEN_FILE`. `SLACK_TOKEN` or `SLACK_BOT_TOKEN` in the environment is
refused. `SLACK_CHANNELS` limits the scan to named channel ids. A channel
the bot is not a member of is `not_a_member`.

**Direct messages** are readable only through Slack's **Discovery API**, on
**Enterprise Grid**, by an org-level app Slack has approved for
`discovery:read` (Slack grants it to eDiscovery and DLP partners and to
organizations on request). Its token (`xoxp-…`, in `SLACK_TOKEN_FILE`) reads
`discovery.conversations.list` (`only_im`, `only_mpim`) and
`discovery.conversations.history`. Until you have it, name `slack_dm` in
`DISCOVER` only to see it as `access_denied` (`not_allowed_token_type` or
`missing_scope`); left out, it is `read_not_configured`.

### What is read

Each channel's messages, newest first, down to what the last complete read
saw (the first run: `LOOKBACK_DAYS`), with each thread's replies read along
with its first message (a reply added later to a thread already read is not
seen), a message's legacy attachments' text, and its files, downloaded from
`files.slack.com` with ranged GETs and read by the core's readers (a file
hosted elsewhere is `linked_item`). At most `MESSAGES_MAX_PER_CHANNEL`
messages a channel a run; the next run goes on below where this one stopped.
Slack's `Retry-After` is honored. The token is sent to `slack.com` and
`files.slack.com` only.

Slack encrypts its data with its own keys (`service_managed`); with **Slack
Enterprise Key Management**, set `SLACK_EKM_KEY_ID` to your key's id: findings
say `customer_managed_key`, with its hash. Findings link to the channel in
Slack (`https://app.slack.com/client/<team>/<channel>`); a direct message has
no link.

## Findings

A SaaS document says `"platform": "saas"` and names its `site`
(`SCANNER_SITE`). Every finding is a `saas_item` resource:

| Field | What |
|---|---|
| `vendor` | `m365`, `google_workspace`, `slack` |
| `service` | `exchange`, `onedrive`, `sharepoint`, `teams_channel`, `teams_chat`; `gmail`, `drive`, `shared_drive`; `channel`, `dm` |
| `tenantHash` | SHA-256 of the tenant id, lower-case (Microsoft 365: the Entra tenant id; Google Workspace: the customer id; Slack: the Enterprise Grid organization's id, else the workspace's) |
| `ownerHash` | SHA-256 of the mailbox's, OneDrive's or chat's owner (principal name, lower-case) |
| `container`, `channel` | The site and library, or the team and channel, masked like keys |
| `itemId`, `itemHash` | The vendor's id for the item (a message id, `message/attachment`, a drive item id), masked, and its SHA-256 |
| `part` | `message` (a subject and body), `attachment`, `file`, `reply` |
| `name` | A file's or attachment's name, masked like a key |
| `column` | For a table file, the column |

A store in the run summary carries `vendor`, `tenantHash` and, for a person's
store, `ownerHash`. A finding's `link` opens the item in the vendor's own web
app, built from ids only, and is `null` when an id it carries had to be
masked: a message in Outlook on the web (its owner or a delegate opens it), a
SharePoint or OneDrive file by its unique id, a Teams channel, a Google Drive
file by its id, a Slack channel.

## Settings

| Setting | Default | What |
|---|---|---|
| `SCANNER_SITE` | (required) | A name for this deployment, as findings name it |
| `DISCOVER` | every default kind of each configured vendor | Kinds to read, comma-separated, or `all` (with the opt-in kinds) |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | | The core's rules by kind and store name: `m365_sharepoint:HR*`, `m365_mail:user-0123456789abcdef` |
| `DISCOVER_SAMPLING` | | The core's per-store sampling |
| `SAMPLE_PERCENT` | 100 | The share of items read, by a stable hash of the item's id |
| `MAIL_MAX_MESSAGES_PER_MAILBOX` | 500 | Messages read per mailbox per run |
| `FILES_MAX_PER_DRIVE` | 200 | Files read per library or OneDrive per run |
| `MESSAGES_MAX_PER_CHANNEL` | 1000 | Teams messages read per team, or per person's chats, per run |
| `LOOKBACK_DAYS` | 90 | How far back the first run reads mail and messages |
| `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES`, `COLUMNAR_MAX_ROWS` | 20 MiB, 100 MiB, 10000 | Per file or attachment |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS` | 20000, 2 GiB, 3000 | The run's budget, shared among the stores |
| `MAX_THROTTLE_WAIT_SECONDS` | 120 | The longest `Retry-After` waited for; a longer one stops that store until the next run (`throttled`) |
| `STATE_LOCATION` | | Where cursors and carried findings are kept: an absolute path on a mounted volume, `s3://bucket/key`, or `https://…` (signed PUTs with the push key). Without it every run starts afresh |
| `FINDINGS_HTTPS_URL`, `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | | The core's signed HTTPS push to Mermera's collector ([DATABASES.md](DATABASES.md#verifying-a-push)) |
| `FINDINGS_FILE` | | Also write the document to a file |
| `M365_TENANT_ID`, `M365_CLIENT_ID` | | The tenant and the app (GUIDs); set to scan Microsoft 365 |
| `M365_CERTIFICATE_FILE`, `M365_FEDERATED_TOKEN`, `M365_CLIENT_SECRET_FILE` | | The credential: exactly one ([Signing in](#signing-in)) |
| `M365_FEDERATED_AUDIENCE`, `M365_FEDERATED_CLIENT_ID` | `api://AzureADTokenExchange` | The federated token's audience; a user-assigned managed identity's client id |
| `M365_USERS`, `M365_GROUPS` | | Whose mailboxes, OneDrives and chats are read |
| `M365_MAIL_SCOPE_CHECK` | | A mailbox outside the mail scope ([Mail](#mail-scoped-by-exchange-and-proved-scoped)) |
| `M365_SITES` | | SharePoint sites, or `all` |
| `M365_TEAMS` | | Team ids whose channels are read |
| `M365_CUSTOMER_KEY_ID` | | Your Customer Key data encryption policy's id |
| `GWS_CUSTOMER_ID` | | The Workspace customer id (`C0…`); set to scan Google Workspace |
| `GWS_SERVICE_ACCOUNT` | | The delegated service account's email |
| `GWS_ADMIN_USER` | | The administrator for the Directory API and shared drives |
| `GWS_CREDENTIAL`, `GWS_WORKLOAD_PROVIDER`, `GWS_KEY_FILE` | | Who signs ([Who signs](#who-signs-keyless-where-possible)): exactly one of `GWS_CREDENTIAL` and `GWS_KEY_FILE` |
| `GWS_USERS`, `GWS_GROUPS`, `GWS_ORG_UNITS` | | Whose Gmail and My Drive are read |
| `GWS_SHARED_DRIVES` | | Shared drive ids, or `all` |
| `SLACK_TOKEN_FILE` | | The Slack app's token, in a file; set to scan Slack |
| `SLACK_CHANNELS` | every channel the token lists | Channel ids to read |
| `SLACK_EKM_KEY_ID` | | Your Slack EKM key's id |

At least one of `FINDINGS_HTTPS_URL` and `FINDINGS_FILE` is required.

## Running it

```sh
docker build --target saas -t sensitive-data-scanner-saas .
# Discovery only: signs in, resolves the people in scope, runs the mail scope check and
# lists every store; reads no content and sends nothing. Exit 2 if a listing failed.
docker run --rm --env-file saas.env -v /run/secrets/sds:/run/secrets/sds:ro \
  sensitive-data-scanner-saas check
docker run --rm --env-file saas.env -v /run/secrets/sds:/run/secrets/sds:ro \
  -v sds-state:/state sensitive-data-scanner-saas scan
```

Run one scan at a time (a scheduled job with no overlap). Logs are JSON lines
with fixed event names; every string in them is masked, and no address, token
or secret is ever logged.
