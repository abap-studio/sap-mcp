# sap-mcp

MCP server for SAP S/4HANA via the ADT API. Runs locally over stdio.

## Local PDF Encryptor

This repository also includes a separate local browser tool for password-protecting PDFs. It lists folders and PDF files on this computer and saves an AES-256 encrypted copy beside the selected original.

Requirements: Node.js 20.12+ and an internet connection the first time the encryption engine loads. The PDF encryption engine runs as WebAssembly in the browser, so qpdf does not need to be installed on Windows.

Start the tool:

```bash
npm run pdf-encryptor
```

On Windows PowerShell, use `npm.cmd run pdf-encryptor` if the `npm` command is blocked by the script execution policy. Keep that terminal open while using the app. Open the URL printed in the terminal (normally `http://127.0.0.1:4177`), use **Browse…** to choose a folder or enter its path, and select a PDF. The PDF is encrypted in the browser and the output is saved beside the original as `<original>_encrypted.pdf`; existing output files are never overwritten. The server listens only on the local computer. If the default port is already in use, it automatically tries the next port. Set `PDF_ENCRYPTOR_PORT` to choose a starting port.

## Setup on a new machine

**Prerequisites** (install these first):

- **Node.js >= 20.12** (needs `process.loadEnvFile`; also provides `npm`) — required
- **Claude Code** — required to use the server (only the registration step needs it)
- **Network/VPN reachability** to your SAP hosts (e.g. `fiori-dev...`) — required
- **git** — optional; only used for `git clone`. No git? See below.
  (To install on Windows: `winget install --id Git.Git -e`, then **reopen your
  terminal**. macOS: `brew install git`. Verify with `git --version`.)

Then:

```bash
git clone https://github.com/abap-studio/sap-mcp.git
cd sap-mcp
npm install
cp .env.example .env      # PowerShell/CMD: copy .env.example .env
```

> **No git?** Instead of `git clone`, download the repo from GitHub: green
> **Code** button -> **Download ZIP**, unzip it, then `cd` into the folder and
> continue from `npm install`. (git is only nicer later, for pulling updates
> with `git pull` instead of re-downloading.)

Now **edit `.env`** and fill in the real `HOST`/`CLIENT` for each system plus
**your own** SAP `USER`/`PASS`. The real hostnames are intentionally not in this
repo — get them from whoever maintains it. Then verify and register:

```bash
node test.mjs             # PASS = install OK  (does NOT check credentials)
node test.mjs --live      # PASS = credentials + SAP reachable  <-- the real proof

# Register with Claude Code (use the ABSOLUTE path to server.js on this machine):
claude mcp add sap-adt --scope user -- node C:\Users\<name>\sap-mcp\server.js
```

Start a **fresh Claude Code session** afterwards for the server to load.

> `node test.mjs` reports PASS even before you edit `.env` — it only checks that
> the server boots and loads profiles. `node test.mjs --live` is what actually
> confirms your credentials and SAP connectivity.

## Updating an existing install

If you already have sap-mcp set up, pull the latest and **restart Claude Code**:

```bash
cd sap-mcp
git pull            # no git? re-download the ZIP over your folder (keep your .env)
npm install         # only needed if dependencies changed; harmless to run anyway
node test.mjs       # confirm it still boots
```

You do **not** need to re-run `claude mcp add` — the registration persists. Your
`.env` is never touched by an update (it's gitignored), so your credentials and
profiles carry over.

> **Important — quit and restart Claude Code after updating.** New tools are only
> discovered when a Claude Code session **starts**. If an update adds a tool
> (like `create_program` below), a reconnect or `/mcp` refresh is **not** enough:
> fully quit Claude Code and open a fresh session. (Behaviour-only changes to
> existing tools just need the server to respawn, which a new session also does.)

To confirm the update loaded, start a fresh session and ask Claude to run
`list_servers`, or check that the new tool is available.

### What's new (2026-07)

This release roughly doubles the toolset (25 → 45). **These are new tools, so you
must fully quit and restart Claude Code after updating** (see the note above).

- **Source editors for the objects that were create-only.** You could previously
  create a class but never edit one — that's fixed:
  `update_class` / `patch_class`, `update_bdef` / `patch_bdef`,
  `update_srvd` / `patch_srvd`, `update_cds` / `patch_cds`,
  `update_function_module`. Each locks → writes → unlocks and can activate;
  the `patch_*` variants do a surgical exact-string replace and refuse to write
  when the target text matches zero or more than one time.
- **`syntax_check`** — run ADT's syntax/consistency check on an object *without*
  activating it. Read-only and safe on any profile, including production. Use it
  after writing source and before `activate_object`; pass `version:"inactive"`
  to check source you have saved but not yet activated.
- **New object types**: `create_structure` / `update_structure` /
  `patch_structure` (DDIC structures), `create_interface` / `update_interface` /
  `patch_interface`, `create_ddlx` / `update_ddlx` / `patch_ddlx` (CDS metadata
  extensions — the UI annotations a Fiori Elements app needs),
  `create_domain`, `create_data_element`,
  `create_function_group`, `create_function_module`.
- **`where_used`** — the ADT where-used list: find everything that depends on an
  object before you change or delete it. Read-only; results are capped and the
  true total is always reported (a common table can have tens of thousands).
- **`run_atc`** — run an ATC (ABAP Test Cockpit) static-analysis check on an
  object and report the findings. Read-only. Picks up the system's configured
  check variant automatically. Use `syntax_check` for fast error checking and
  `run_atc` before releasing a transport.
- **`list_transports`** — find your open transport requests, so you can pass a
  real request number to the create/update tools.
- **Fix:** `get_object_info` now sends `Accept: */*`, so DDIC metadata (domains,
  data elements, tables) is readable instead of failing with HTTP 406.
- **`update_table` / `patch_table`** — modify an EXISTING DDIC table's source:
  `update_table` overwrites the whole definition, `patch_table` does a surgical
  exact-string replace (add/change a field). Both lock → write → unlock and
  optionally activate; blocked on production. Mirrors the
  `update_program_source` / `patch_program_source` pair. **New tools — restart
  Claude Code after updating** (see above).
- **`create_program`** — create a brand-new classic ABAP report (executable
  program, `PROG/P`) and activate it in one call. Previously the server could
  only *edit* an existing program; now it can create one from scratch. Refuses
  to run on production profiles. **This is a new tool, so you must restart
  Claude Code after updating** (see above).
- **`insert_table_record` / `update_table_record`** — insert or update one row
  in a custom `Z*`/`Y*` table through a temporary ABAP classrun. Updates require
  key fields that match exactly one row; both tools require `confirm: true` and
  are blocked on read-only profiles. **Restart the MCP client after updating**
  so it discovers the new tools.
- **Data-driven profiles** — profiles are now discovered from your `.env`: every
  `SAP_<KEY>_HOST` you define becomes a switchable profile named `<KEY>`, with no
  code change needed to add a system. Profile switching is case-insensitive.
- **Production write-block widened** — writes are now blocked on both `ABLP`
  (production) and `ABLQ` (QAS). Read access still works on every profile.

## Testing your install

The `node test.mjs` / `node test.mjs --live` steps above are the self-check
(`npm test` runs the structural one). The bundled harness talks to the server
over stdio — no Claude Code needed.

Once registered, you can also verify through Claude Code — ask it to run
`list_servers`, or a `query_table` with `SELECT MANDT, MTEXT FROM T000`.

## Credentials

Each person uses their **own named SAP user** per system. All connection
details and credentials live in `.env` (gitignored); `server.js` contains no
real hostnames. Never commit or share `.env` — sharing a service account breaks
the SE24/transport audit trail and usually violates license terms.

Fill in `HOST`, `CLIENT`, `USER` and `PASS` for each profile in `.env`. Every
`SAP_<KEY>_HOST` you define becomes a switchable profile named `<KEY>` — the
list below is illustrative, not fixed, so add or rename systems freely:

| Profile  | Role                     |
|----------|--------------------------|
| `ABLD`   | Development              |
| `dev120` | Development (client 120) |
| `snet`   | QA/Test                  |
| `ABLQ`   | QAS (read-only)          |
| `ABLP`   | Production               |
| `snet2`  | S/4HANA on-prem          |

### Protecting a system from writes

Add a `READONLY` (or `PROD`) flag next to any profile in `.env` and every write
on it — create, edit, activate — is refused. Reads keep working:

```bash
SAP_PRD2_HOST="https://sap-prd2.example.com:44300"
SAP_PRD2_CLIENT="100"
SAP_PRD2_USER=""
SAP_PRD2_PASS=""
SAP_PRD2_READONLY=true      # or SAP_PRD2_PROD=true
```

Accepted values: `true` / `1` / `yes` / `y` / `X`. **Do this for every
production system you add** — no code change needed. Add
`SAP_PRD2_LABEL="Production"` to control how the profile is described by
`list_servers`.

> The flag protects a **profile**, not a system. If two profiles point at the
> same host *and* client, flag both — otherwise writes still reach that client
> through the unflagged one.

`ABLP` and `ABLQ` are *also* blocked by a built-in list in `server.js`, so they
stay protected even if the flag is missing. The two sources are **additive**: a
missing flag can never unblock a system that was protected before.

Run `list_servers` to confirm — protected profiles are shown as `[read-only]`.
A blocked write reports which rule stopped it.

## Disclaimer

This software is provided **"as is", without warranty of any kind**, express or
implied. You use it entirely **at your own risk**.

- **No liability.** The author accepts no responsibility for any damage, data
  loss, downtime, security incident, or other harm — to your computer, your SAP
  systems, or your data — arising from the use, misuse, or inability to use this
  software.
- **Your access, your responsibility.** You supply your own SAP credentials in
  `.env`. Keep that file private, use your own named user, and connect only to
  systems you are authorized to access.
- **Production risk remains.** Writes to the `ABLP` (production) profile are
  blocked, but the tool can still *read* from any system you configure. Use it
  at your own discretion.
- **Compliance is on you.** Ensure your use complies with your organization's
  policies and your SAP license terms before connecting.
- **Not affiliated with SAP.** SAP and S/4HANA are trademarks of SAP SE. This
  is an independent, unofficial tool and is not endorsed by or affiliated with
  SAP SE.

## License

[MIT](LICENSE). The license text includes the binding "as is" / no-warranty /
no-liability terms; the Disclaimer above restates them in plain language.
