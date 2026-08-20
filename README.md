# hexcollab

## Setup

Requirements: Docker, Docker Compose, Node.js >= 20.

```bash
chmod +x install.sh hexcollab.js
./install.sh
```

This one script does everything: starts ONLYOFFICE Document Server locally
with JWT on (mounting `documentserver-local.json` to raise the default
100MB file size limit), configures hexcollab to use it, compiles a
standalone `hexcollab` binary, and installs it to your PATH.

Needs internet access once during the build step, to fetch `postject` via
`npx`. The binary is platform-specific — run `./install.sh` again on each
OS you plan to run it on.

### For internet sharing, also run:

```bash
hexcollab cloudflare setup rezydev.com
```

Opens a browser to authenticate with your Cloudflare account, creates a
tunnel, and routes `hex.rezydev.com` / `docs.rezydev.com` to it.

> Requires a domain added to your Cloudflare account. Skip if you only need
> LAN sharing.

## Workflow

Share a file:

```
hexcollab share proposal.docx
```

Prompts you to set a password (leave blank to auto-generate a 25-character
one). Prints the join URL and the password, every session requires both to
open. Give both to your colleagues.

Manage sessions:

```bash
hexcollab list
hexcollab info <id>
hexcollab passwd <id>
hexcollab stop <id>
hexcollab stop --all
```

`passwd` rotates a session's password (same prompt/auto-generate behavior
as `share`).

#### Share the same session over the internet:

```bash
hexcollab tunnel <id>
```

Uses your configured Cloudflare tunnel if `cloudflare setup` was run
(stable link, prints immediately); otherwise starts temporary tunnels and
prints a one-off link that lasts until you press Ctrl+C.

```bash
hexcollab cloudflare start
hexcollab cloudflare stop
```

### When does it actually save to disk?

Live edits sync between collaborators instantly, but the file on disk only
updates when either: everyone closes the editor tab, or someone presses
Ctrl+S / the Save button while still editing. If you're testing solo and
wondering why the local file hasn't changed yet, press Ctrl+S or close the
tab.

Change settings:

```
hexcollab config
hexcollab config <key> <value>
```

Stop everything:

```
hexcollab kill
docker compose down
```
