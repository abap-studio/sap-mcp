import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import https from "https";
import path from "path";
import { fileURLToPath } from "url";

// Credentials live in sap-mcp/.env and must never be written into this file.
// A launcher-supplied environment (e.g. the MCP config "env" block) also works;
// anything already in process.env wins over the file.
try {
  process.loadEnvFile(path.join(path.dirname(fileURLToPath(import.meta.url)), ".env"));
} catch {
  // No .env present - fall back to the ambient environment.
}

// Profiles are DISCOVERED from .env: every SAP_<KEY>_HOST defines a profile
// named <KEY>, with matching SAP_<KEY>_CLIENT / _USER / _PASS. Add or edit a
// profile by editing .env - no code change needed.
//
// Display names come from SAP_<KEY>_LABEL in .env when present. The map below
// is only a fallback for the profiles this connector shipped with, so a new
// system can be named without touching this file.
const PROFILE_LABELS = {
  DEV: "Development",
  QAS: "Quality Assurance",
  PRD: "Production",
};

// Accepts the spellings people actually use for a boolean in a .env / in SAP.
function envFlag(value) {
  return /^(true|1|yes|y|x)$/i.test(String(value || "").trim());
}

function discoverProfiles() {
  const out = {};
  for (const name of Object.keys(process.env)) {
    const m = /^SAP_(.+)_HOST$/.exec(name);
    if (!m) continue;
    const key = m[1];
    // SAP_<KEY>_READONLY / _PROD marks a system as write-protected. Either name
    // works; PROD reads better for production, READONLY for anything you just
    // don't want touched.
    const readonly =
      envFlag(process.env[`SAP_${key}_READONLY`]) || envFlag(process.env[`SAP_${key}_PROD`]);
    const envLabel = String(process.env[`SAP_${key}_LABEL`] || "").trim();
    out[key] = {
      // .env wins, then the built-in fallback map, then the bare key.
      label: envLabel || PROFILE_LABELS[key] || key,
      host: process.env[`SAP_${key}_HOST`],
      client: process.env[`SAP_${key}_CLIENT`],
      user: process.env[`SAP_${key}_USER`],
      pass: process.env[`SAP_${key}_PASS`],
      readonly,
    };
  }
  return out;
}

const PROFILES = discoverProfiles();

// Resolve a profile name case-insensitively (so "snet" still matches "SNET").
function resolveProfileKey(name) {
  if (PROFILES[name]) return name;
  const lower = String(name || "").toLowerCase();
  return Object.keys(PROFILES).find((k) => k.toLowerCase() === lower) || null;
}

let activeProfile = PROFILES.ABLD ? "ABLD" : Object.keys(PROFILES)[0] || "ABLD";

// Profiles that must never be written to. Two sources, combined:
//   1. this built-in list (matched case-insensitively), and
//   2. SAP_<KEY>_READONLY=true / SAP_<KEY>_PROD=true in .env.
// They are ADDITIVE on purpose: a missing .env flag can never silently unblock
// a system that was protected before. PRD is blocked by name as a default
// safety net for anyone following the DEV/QAS/PRD convention from
// .env.example - name your production profile something else if you want
// its write protection to depend solely on the .env flag.
const WRITE_BLOCKED_PROFILES = new Set(["PRD"]);
function isWriteBlocked(key) {
  const k = String(key || "").toUpperCase();
  if (WRITE_BLOCKED_PROFILES.has(k)) return true;
  const p = PROFILES[key] || PROFILES[resolveProfileKey(key) || ""] || null;
  return !!(p && p.readonly);
}

function profile() {
  const p = PROFILES[activeProfile];
  if (!p) {
    throw new Error(`Unknown profile: ${activeProfile}. Available: ${Object.keys(PROFILES).join(", ")}`);
  }
  const k = activeProfile.toUpperCase();
  if (!p.host || !p.client) {
    throw new Error(
      `No connection details for profile "${activeProfile}". Set SAP_${k}_HOST and SAP_${k}_CLIENT in sap-mcp/.env`
    );
  }
  if (!p.user || !p.pass) {
    throw new Error(
      `No credentials for profile "${activeProfile}". Set SAP_${k}_USER and SAP_${k}_PASS in sap-mcp/.env`
    );
  }
  return p;
}

function assertWritable() {
  if (isWriteBlocked(activeProfile)) {
    const p = PROFILES[activeProfile] || {};
    const why = p.readonly
      ? `It is marked read-only in .env (SAP_${String(activeProfile).toUpperCase()}_READONLY)`
      : `It is a protected system in this connector's built-in list`;
    throw new Error(
      `Writes are blocked on profile "${activeProfile}" (${p.label || activeProfile}, client ${p.client || "?"}). ` +
      `${why}. Switch to a development profile first.`
    );
  }
}

const agent = new https.Agent({ rejectUnauthorized: false });

function authHeaders(accept = "application/xml") {
  const p = profile();
  const token = Buffer.from(`${p.user}:${p.pass}`).toString("base64");
  return {
    Authorization: `Basic ${token}`,
    "sap-client": p.client,
    Accept: accept,
  };
}

async function adtGet(path, accept) {
  const res = await fetch(`${profile().host}${path}`, {
    headers: authHeaders(accept),
    agent,
  });
  if (!res.ok) throw new Error(`SAP ADT error ${res.status}: ${await res.text()}`);
  return res.text();
}

async function fetchCsrfToken() {
  const res = await fetch(`${profile().host}/sap/bc/adt/datapreview/freestyle`, {
    method: "HEAD",
    headers: { ...authHeaders(), "X-CSRF-Token": "Fetch" },
    agent,
  });
  const token = res.headers.get("x-csrf-token");
  const cookies = res.headers.raw()["set-cookie"] || [];
  return { token, cookies: cookies.map(c => c.split(";")[0]).join("; ") };
}

// ADT locking is stateful: the lock, the PUT and the unlock must all ride the
// same session, so cookies set by any response have to be carried forward.
function mergeCookies(existing, res) {
  const jar = new Map();
  for (const c of (existing || "").split("; ").filter(Boolean)) {
    const i = c.indexOf("=");
    if (i > 0) jar.set(c.slice(0, i), c.slice(i + 1));
  }
  for (const c of res.headers.raw()["set-cookie"] || []) {
    const first = c.split(";")[0];
    const i = first.indexOf("=");
    if (i > 0) jar.set(first.slice(0, i), first.slice(i + 1));
  }
  return [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
}

function escapeXml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

// Turns the escaped text inside XML attributes back into readable text.
function decodeXml(s) {
  return String(s ?? "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&amp;/g, "&");
}

// Parses the <msg .../> list an activation returns. An empty body means success.
function parseActivationMessages(xml) {
  if (!xml || !xml.trim()) return [];
  return [...xml.matchAll(/<msg[^>]*\btype="([^"]*)"[^>]*>([\s\S]*?)<\/msg>/g)].map(m => {
    const txt = m[2].match(/<txt>([\s\S]*?)<\/txt>/);
    return { type: m[1], text: txt ? txt[1] : m[2].replace(/<[^>]+>/g, " ").trim() };
  });
}

// Activate an object over a stateful `call`. MUST run AFTER the edit lock is
// released: ADT rejects activation while the object is still locked
// ("<user> is currently editing <object>"). Appends the outcome to `log`.
async function runActivation(call, uri, name, log, kind) {
  const actBody =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">\n` +
    `  <adtcore:objectReference adtcore:uri="${uri}" adtcore:name="${escapeXml(name)}"/>\n` +
    `</adtcore:objectReferences>`;
  const act = await call(`/sap/bc/adt/activation?method=activate&preauditRequests=false`, {
    method: "POST",
    headers: { "Content-Type": "application/xml" },
    body: actBody,
  });
  const msgs = parseActivationMessages(act.text);
  const bad = msgs.filter(m => /^[EAW]$/i.test(m.type));
  if (!act.ok || bad.length) {
    log.push(`ACTIVATION FAILED (HTTP ${act.status}) - the ${kind} exists but is INACTIVE.`);
    for (const m of (bad.length ? bad : msgs)) log.push(`  [${m.type}] ${m.text}`);
    // Never swallow the response: without it there is nothing to debug.
    if (!bad.length) log.push(`  Raw response: ${(act.text || "(empty body)").slice(0, 1500)}`);
  } else {
    log.push("Activated cleanly.");
  }
}

// Shared create-and-activate flow for ADT text-source objects that follow the
// same pattern: CDS view (DDLS), service definition (SRVD), behavior definition
// (BDEF). Create shell -> lock -> PUT source -> unlock -> activate. Activation
// MUST run after unlock (see runActivation). Returns the log text.
async function createSourceObject({ name, uri, createEndpoint, contentType, shell, source, corrNr, activate, kind }) {
  assertWritable();
  const host = profile().host;
  const log = [];

  const { token, cookies: initialCookies } = await fetchCsrfToken();
  let cookies = initialCookies;
  if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

  const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
    const res = await fetch(`${host}${path}`, {
      method,
      headers: {
        ...authHeaders(accept),
        "X-CSRF-Token": token,
        "x-sap-adt-sessiontype": "stateful",
        Cookie: cookies,
        ...headers,
      },
      body,
      agent,
    });
    cookies = mergeCookies(cookies, res);
    return { ok: res.ok, status: res.status, text: await res.text() };
  };

  // 1) create the (empty) object shell
  const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
  const created = await call(`${createEndpoint}${corrQuery}`, {
    method: "POST",
    headers: { "Content-Type": contentType },
    body: shell,
  });
  if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
  log.push(`Created ${kind} ${name}${corrNr ? ` on ${corrNr}` : ""}.`);

  // 2) lock  3) put source  4) unlock — all on the one stateful session
  const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
    method: "POST",
    accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
  });
  if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
  const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
  if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
  log.push("Locked.");

  try {
    const put = await call(
      `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
      (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
      { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
    );
    if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
    log.push(`Source written (${source.split("\n").length} lines).`);
  } finally {
    const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
      method: "POST",
    });
    log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
  }

  // 5) activate AFTER unlocking (activating a still-locked object is rejected)
  if (activate) {
    await runActivation(call, uri, name, log, kind);
  }

  return log.join("\n");
}

// Shared edit flow for ADT text-source objects (class, BDEF, SRVD, function
// module, ...). Reads the current source, applies `transform` to it, then
// locks -> PUTs -> unlocks -> optionally activates. Activation MUST run after
// unlock (see runActivation). Returns the log text.
async function editSourceObject({ name, uri, transform, corrNr, activate, kind, createHint }) {
  assertWritable();
  const host = profile().host;
  const log = [];

  const { token, cookies: initialCookies } = await fetchCsrfToken();
  let cookies = initialCookies;
  if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

  const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
    const res = await fetch(`${host}${path}`, {
      method,
      headers: {
        ...authHeaders(accept),
        "X-CSRF-Token": token,
        "x-sap-adt-sessiontype": "stateful",
        Cookie: cookies,
        ...headers,
      },
      body,
      agent,
    });
    cookies = mergeCookies(cookies, res);
    return { ok: res.ok, status: res.status, text: await res.text() };
  };

  // 1) read the current source (this tool edits; it never creates)
  const probe = await call(`${uri}/source/main`, { method: "GET", accept: "text/plain" });
  if (probe.status === 404) throw new Error(`${kind} ${name} not found. Use ${createHint} to create a new one.`);
  if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);

  // 2) work out the new source - transform() throws if the edit is unsafe
  const before = String(probe.text).replace(/\r\n/g, "\n");
  const after = transform(before, log);
  log.push(`Target: ${uri}`);
  log.push(`Lines ${before.split("\n").length} -> ${after.split("\n").length}.`);

  // 3) lock  4) put source  5) unlock — all on the one stateful session
  const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
    method: "POST",
    accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
  });
  if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
  const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
  if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
  log.push("Locked.");

  let wrote = false;
  try {
    const put = await call(
      `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
      (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
      { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: after }
    );
    if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
    log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
    wrote = true;
  } finally {
    const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
      method: "POST",
    });
    log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
  }

  if (wrote && activate) await runActivation(call, uri, name, log, kind);
  else if (wrote) log.push(`Not activated (activate=false) - activate it yourself or with activate_object.`);

  return log.join("\n");
}

// transform() for a whole-source overwrite.
function wholeSource(source) {
  if (!source || !source.trim()) throw new Error("Refusing to write an empty source - that would wipe the object.");
  return () => String(source).replace(/\r\n/g, "\n");
}

// transform() for a surgical replace. Refuses on 0 or >1 matches so a bad edit
// never half-writes the object.
function replaceOnce(oldString, newString, name) {
  if (!oldString) throw new Error("oldString must not be empty.");
  if (oldString === newString) throw new Error("oldString and newString are identical - nothing to do.");
  const nl = s => String(s).replace(/\r\n/g, "\n");
  const oldNl = nl(oldString);
  const newNl = nl(newString);
  return (before, log) => {
    const hits = before.split(oldNl).length - 1;
    if (hits === 0) {
      const firstLine = oldNl.split("\n")[0].trim();
      const near = firstLine ? before.split("\n").filter(l => l.includes(firstLine)) : [];
      throw new Error(`oldString not found in ${name}. Nothing written.` +
        (near.length ? ` Lines containing the first line of oldString: ${JSON.stringify(near.slice(0, 5))}` : ""));
    }
    if (hits > 1) throw new Error(`oldString matched ${hits} times in ${name}. Nothing written. Add surrounding context to make it unique.`);
    log.push("Patched 1 occurrence.");
    return before.replace(oldNl, newNl);
  };
}

function parseDataPreview(xml) {
  const totalMatch = xml.match(/<dataPreview:totalRows>(\d+)<\/dataPreview:totalRows>/);
  const total = totalMatch ? parseInt(totalMatch[1]) : 0;
  const columns = [...xml.matchAll(/<dataPreview:metadata[^>]*dataPreview:name="([^"]*)"[^>]*dataPreview:description="([^"]*)"/g)]
    .map(m => ({ name: m[1], desc: m[2] }));
  const datasets = [...xml.matchAll(/<dataPreview:dataSet>([\s\S]*?)<\/dataPreview:dataSet>/g)]
    .map(m => [...m[1].matchAll(/<dataPreview:data[^>]*>([^<]*)<\/dataPreview:data>/g)].map(d => d[1].trim()));
  if (columns.length === 0) return { total, rows: [] };
  const rowCount = datasets[0]?.length || 0;
  const rows = Array.from({ length: rowCount }, (_, i) =>
    Object.fromEntries(columns.map((col, j) => [col.name, datasets[j]?.[i] ?? ""]))
  );
  return { total, columns: columns.map(c => c.name), rows };
}

function parseObjectRefs(xml) {
  // Pull each <adtcore:objectReference> element and read its attributes
  // independently. ADT does not emit them in a fixed order (it returns
  // type before name), so an order-dependent regex silently matches nothing.
  const refs = [];
  for (const m of xml.matchAll(/<adtcore:objectReference\b[^>]*?\/?>/g)) {
    const tag = m[0];
    const attr = (n) => (tag.match(new RegExp(`adtcore:${n}="([^"]*)"`)) || [])[1] || "";
    const name = attr("name");
    if (name) {
      refs.push({
        name,
        type: attr("type"),
        package: attr("packageName"),
        description: attr("description"),
      });
    }
  }
  return refs;
}

const server = new McpServer({
  name: "sap-adt",
  version: "1.0.0",
});

server.tool(
  "list_servers",
  "List all available SAP server profiles and show which one is currently active",
  {},
  async () => {
    const lines = Object.entries(PROFILES).map(([key, p]) => {
      const active = key === activeProfile ? " ◀ active" : "";
      const creds = p.user && p.pass ? "" : "  [NO CREDENTIALS - check .env]";
      const ro = isWriteBlocked(key) ? "  [read-only]" : "";
      return `${key}: ${p.label} | ${p.host} | client ${p.client}${ro}${creds}${active}`;
    });
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "switch_server",
  "Switch the active SAP server profile by name",
  {
    profile: z.string().describe("Profile name to switch to, e.g. dev, prod"),
  },
  async ({ profile: name }) => {
    const key = resolveProfileKey(name);
    if (!key) {
      const available = Object.keys(PROFILES).join(", ");
      return { content: [{ type: "text", text: `Profile "${name}" not found. Available: ${available}` }] };
    }
    activeProfile = key;
    const p = PROFILES[key];
    return { content: [{ type: "text", text: `Switched to profile "${key}": ${p.label} (${p.host}, client ${p.client})` }] };
  }
);

server.tool(
  "search_programs",
  "Search ABAP programs in SAP S/4HANA by name pattern (use * as wildcard)",
  {
    query: z.string().describe("Search pattern, e.g. Z* or ZFIN* or ZMYPROGRAM"),
    maxResults: z.number().optional().default(20).describe("Max number of results"),
    objectType: z.enum(["PROG", "FUGR", "CLAS", "INTF", "TABL", "VIEW"]).optional().default("PROG").describe("Object type"),
  },
  async ({ query, maxResults, objectType }) => {
    const xml = await adtGet(
      `/sap/bc/adt/repository/informationsystem/search?operation=quickSearch&query=${encodeURIComponent(query)}&maxResults=${maxResults}&objectType=${objectType}`
    );
    const refs = parseObjectRefs(xml);
    if (refs.length === 0) return { content: [{ type: "text", text: "No programs found." }] };
    const lines = refs.map(r => `${r.name} (${r.type}) | Package: ${r.package} | ${r.description}`);
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "get_program_source",
  "Read the ABAP source code of a program from SAP S/4HANA",
  {
    programName: z.string().describe("Exact program name, e.g. ZMYPROGRAM"),
  },
  async ({ programName }) => {
    const name = programName.toLowerCase();
    // Reports/programs live under programs/programs; includes under programs/includes.
    // Try program path first, fall back to include path on 404 (not found).
    const paths = [
      `/sap/bc/adt/programs/programs/${name}/source/main`,
      `/sap/bc/adt/programs/includes/${name}/source/main`,
    ];
    let lastErr;
    for (const path of paths) {
      try {
        const xml = await adtGet(path, "text/plain");
        return { content: [{ type: "text", text: xml }] };
      } catch (e) {
        lastErr = e;
        // Only fall through when the object wasn't found; rethrow real errors.
        if (!/error 404/i.test(String(e && e.message))) throw e;
      }
    }
    throw lastErr;
  }
);

server.tool(
  "get_class_source",
  "Read the ABAP source code of a class's main include (definition + implementation) from SAP S/4HANA",
  {
    className: z.string().describe("Exact class name, e.g. ZCL_MY_CLASS"),
  },
  async ({ className }) => {
    const xml = await adtGet(`/sap/bc/adt/oo/classes/${className.toLowerCase()}/source/main`, "text/plain");
    return { content: [{ type: "text", text: xml }] };
  }
);

server.tool(
  "get_cds_source",
  "Read the DDL source of a CDS view from SAP S/4HANA",
  {
    cdsName: z.string().describe("Exact CDS view name, e.g. ZI_MY_VIEW"),
  },
  async ({ cdsName }) => {
    const xml = await adtGet(`/sap/bc/adt/ddic/ddl/sources/${cdsName.toLowerCase()}/source/main`, "text/plain");
    return { content: [{ type: "text", text: xml }] };
  }
);

server.tool(
  "get_outline",
  "Get the structural outline of an ABAP object — lists its components such as includes, " +
  "FORM routines, local class definitions, selection screens, and events without reading the " +
  "full source. Essential for navigating large standard SAP programs before deciding which " +
  "includes to fetch. Pass the object's ADT URI without '/source/main', " +
  "e.g. /sap/bc/adt/programs/programs/myprog or /sap/bc/adt/oo/classes/zcl_myclass.",
  {
    objectUri: z.string().describe(
      "ADT URI of the ABAP object (no '/source/main' suffix), e.g. " +
      "/sap/bc/adt/programs/programs/saplmm07 or /sap/bc/adt/oo/classes/cl_mm_po_outbound"
    ),
  },
  async ({ objectUri }) => {
    const xml = await adtGet(objectUri, "application/vnd.sap.adt.objectStructure.v3+xml");
    const items = [];
    for (const m of xml.matchAll(/<adtcore:objectReference\b([\s\S]*?)(?:<\/adtcore:objectReference>|\/>)/g)) {
      const block = m[0];
      const attr = (n) => (block.match(new RegExp(`adtcore:${n}="([^"]*)"`)) || [])[1] || "";
      const name = attr("name");
      const type = attr("type");
      const desc = decodeXml(attr("description"));
      const lineMatch = block.match(/adtcore:name="line"\s[^>]*adtcore:value="(\d+)"/);
      const line = lineMatch ? lineMatch[1] : null;
      if (name && type) items.push({ name, type, desc, line });
    }
    if (items.length === 0) return { content: [{ type: "text", text: xml }] };
    const lines = items.map(i => {
      let s = `${i.type.padEnd(12)} ${i.name}`;
      if (i.desc) s += `  — ${i.desc}`;
      if (i.line) s += `  (line ${i.line})`;
      return s;
    });
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "list_package_objects",
  "List all repository objects inside an SAP package (programs, classes, CDS views, tables, " +
  "structures, data elements, domains, function groups, and everything else in it)",
  {
    packageName: z.string().describe("Package name, e.g. ZMYPACKAGE"),
    maxResults: z.number().optional().default(100).describe("Max number of objects to return (default 100)"),
  },
  async ({ packageName, maxResults }) => {
    // No objectType filter - omitting it entirely is what makes ADT's
    // quickSearch return every object type in the package instead of just
    // one. A previous version hardcoded objectType=PROG here, so this tool
    // silently only ever showed programs/includes, despite its own
    // description promising "all repository objects".
    const xml = await adtGet(
      `/sap/bc/adt/repository/informationsystem/search?operation=quickSearch&query=*&maxResults=${maxResults}&packageName=${encodeURIComponent(packageName)}`
    );
    const refs = parseObjectRefs(xml);
    if (refs.length === 0) return { content: [{ type: "text", text: `No objects found in package ${packageName}.` }] };
    const lines = refs.map(r => `${r.name} (${r.type}) | ${r.description}`);
    const capped = refs.length >= maxResults ? `\n\n(hit the ${maxResults}-result cap - raise maxResults if this package has more.)` : "";
    return { content: [{ type: "text", text: lines.join("\n") + capped }] };
  }
);

server.tool(
  "get_object_info",
  "Get metadata/details about an ABAP object (program, function group, class, etc.)",
  {
    objectUri: z.string().describe("ADT URI of the object, e.g. /sap/bc/adt/programs/programs/zmyprogram"),
  },
  async ({ objectUri }) => {
    // ADT source endpoints only serve text/plain; metadata endpoints serve XML
    // but reject a missing/narrow Accept with HTTP 406 (esp. DDIC domains,
    // data elements, tables), so ask for */* there.
    const accept = /\/source\/main\b/.test(objectUri) ? "text/plain" : "*/*";
    const xml = await adtGet(objectUri, accept);
    return { content: [{ type: "text", text: xml }] };
  }
);

server.tool(
  "get_table_info",
  "Get structure and field definitions of a SAP DDIC table or structure (e.g. EKKO, MARA, BSEG). " +
  "Works for both transparent tables (TABL/TRANSP) and structures (TABL/DS) - falls back automatically.",
  {
    tableName: z.string().describe("Table or structure name, e.g. EKKO"),
  },
  async ({ tableName }) => {
    const name = tableName.toUpperCase();
    const nameLower = tableName.toLowerCase();
    let kind = "Table";
    let meta, source;
    try {
      [meta, source] = await Promise.all([
        adtGet(`/sap/bc/adt/ddic/tables/${nameLower}`, "*/*"),
        adtGet(`/sap/bc/adt/ddic/tables/${nameLower}/source/main`, "text/plain"),
      ]);
    } catch (err) {
      // Not every DDIC object with fields is a transparent table - structures
      // (TABL/DS, e.g. ACDOCA extension includes) 404 on the tables endpoint
      // ("Error while importing object ... from the database") because they
      // have no physical database representation. Retry against the
      // structures endpoint before giving up, so the caller doesn't need to
      // already know the object's exact DDIC subtype.
      kind = "Structure";
      [meta, source] = await Promise.all([
        adtGet(`/sap/bc/adt/ddic/structures/${nameLower}`, "*/*"),
        adtGet(`/sap/bc/adt/ddic/structures/${nameLower}/source/main`, "text/plain"),
      ]);
    }
    const descMatch = meta.match(/adtcore:description="([^"]*)"/);
    const description = descMatch ? descMatch[1] : "";
    return {
      content: [{
        type: "text",
        text: `${kind}: ${name}\nDescription: ${description}\n\n--- Field Definitions ---\n${source}`,
      }],
    };
  }
);

server.tool(
  "query_table",
  "Run a SQL SELECT query against SAP tables and return results as a formatted table",
  {
    sql: z.string().describe("SQL SELECT statement, e.g. SELECT EBELN, BSART FROM EKKO"),
    maxRows: z.number().optional().default(20).describe("Maximum rows to return (default 20)"),
  },
  async ({ sql, maxRows }) => {
    try {
    const { token, cookies } = await fetchCsrfToken();
    const res = await fetch(
      `${profile().host}/sap/bc/adt/datapreview/freestyle?maxRows=${maxRows}&rowNumber=0`,
      {
        method: "POST",
        headers: {
          ...authHeaders("application/vnd.sap.adt.datapreview.table.v1+xml"),
          "Content-Type": "text/plain",
          "X-CSRF-Token": token,
          Cookie: cookies,
        },
        body: sql,
        agent,
      }
    );
    if (!res.ok) throw new Error(`SAP ADT error ${res.status}: ${await res.text()}`);
    const xml = await res.text();
    const { total, columns, rows } = parseDataPreview(xml);
    if (rows.length === 0) return { content: [{ type: "text", text: `Query returned 0 rows. Total in table: ${total}` }] };
    const header = columns.join(" | ");
    const divider = columns.map(c => "-".repeat(c.length)).join("-|-");
    const dataRows = rows.map(r => columns.map(c => r[c]).join(" | "));
    const text = [header, divider, ...dataRows, `\n(${rows.length} of ${total} rows)`].join("\n");
    return { content: [{ type: "text", text }] };
    } catch(e) {
      throw new Error(`query_table failed: ${e.stack || e.message}`);
    }
  }
);

server.tool(
  "create_class",
  "Create a new ABAP class in SAP and activate it. Refuses to run on production profiles. " +
  "Needs the full source (CLASS...DEFINITION...ENDCLASS. CLASS...IMPLEMENTATION...ENDCLASS.) " +
  "and a transport request when the package is transportable.",
  {
    className: z.string().describe("Class name, e.g. ZCLAB_IF_PO_IN_NS"),
    description: z.string().describe("Short description shown in SE24"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway class."),
    source: z.string().describe("Complete ABAP source of the class"),
    transport: z.string().optional().describe("Transport request, e.g. ABLK900123. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ className, description, packageName, source, transport: corrNr, activate }) => {
    assertWritable();

    const name = className.toUpperCase();
    const uri = `/sap/bc/adt/oo/classes/${className.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    };

    // 1) create the (empty) class shell
    const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<class:abapClass xmlns:class="http://www.sap.com/adt/oo/classes" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="CLAS/OC" ` +
      `adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN" ` +
      `class:final="true" class:visibility="public">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</class:abapClass>`;

    const created = await call(`/sap/bc/adt/oo/classes${corrQuery}`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.sap.adt.oo.classes.v2+xml" },
      body: shell,
    });
    if (!created.ok) {
      throw new Error(`Create failed (${created.status}). ${created.text}`);
    }
    log.push(`Created shell ${name} in package ${packageName.toUpperCase()}${corrNr ? ` on ${corrNr}` : ""}.`);

    // 2) lock  3) put source  5) unlock — all on the one stateful session
    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written (${source.split("\n").length} lines).`);
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    // Activate AFTER the edit lock is released - activating a still-locked
    // object is rejected by ADT ("... is currently editing ...").
    if (activate) {
      await runActivation(call, uri, name, log, "class");
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "create_program",
  "Create a new classic ABAP program (executable report, type PROG/P) in SAP and activate it. " +
  "Refuses to run on production profiles. Needs the full report source (REPORT ... / logic) and a " +
  "transport request when the package is transportable (omit for $TMP local programs).",
  {
    programName: z.string().describe("Program name, e.g. ZHELLO_WORLD"),
    description: z.string().describe("Short description shown in SE38/SE80"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway program."),
    source: z.string().describe("Complete ABAP report source"),
    transport: z.string().optional().describe("Transport request, e.g. ABLK900123. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ programName, description, packageName, source, transport: corrNr, activate }) => {
    assertWritable();
    if (!source || !source.trim()) throw new Error("Refusing to create a program with empty source.");

    const name = programName.toUpperCase();
    const uri = `/sap/bc/adt/programs/programs/${programName.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    };

    // 1) create the (empty) program shell
    const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<program:abapProgram xmlns:program="http://www.sap.com/adt/programs/programs" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="PROG/P" ` +
      `adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</program:abapProgram>`;

    const created = await call(`/sap/bc/adt/programs/programs${corrQuery}`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.sap.adt.programs.programs.v2+xml" },
      body: shell,
    });
    if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
    log.push(`Created shell ${name} in package ${packageName.toUpperCase()}${corrNr ? ` on ${corrNr}` : ""}.`);

    // 2) lock  3) put source  4) unlock — one stateful session
    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written (${source.split("\n").length} lines).`);
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    // Activate only after the edit lock is released.
    if (activate) {
      await runActivation(call, uri, name, log, "program");
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "create_include",
  "Create a new classic ABAP INCLUDE program (type PROG/I) in SAP and activate it - a SEPARATE ADT " +
  "collection from create_program's executable reports (PROG/P), verified against the open-source " +
  "abap-adt-api client rather than guessed: /sap/bc/adt/programs/includes, not /programs/programs. " +
  "Refuses to run on production profiles. No INCLUDE statement is added to any main program here - do that " +
  "separately with patch_program_source on the program that should include it.",
  {
    includeName: z.string().describe("Include name, e.g. ZHELLO_WORLDTOP"),
    description: z.string().describe("Short description shown in SE38/SE80"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway include."),
    source: z.string().describe("Complete ABAP source for the include"),
    transport: z.string().optional().describe("Transport request, e.g. ABLK900123. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ includeName, description, packageName, source, transport: corrNr, activate }) => {
    assertWritable();
    if (!source || !source.trim()) throw new Error("Refusing to create an include with empty source.");

    const name = includeName.toUpperCase();
    const uri = `/sap/bc/adt/programs/includes/${includeName.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    };

    // 1) create the (empty) include shell
    const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<include:abapInclude xmlns:include="http://www.sap.com/adt/programs/includes" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="PROG/I" ` +
      `adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</include:abapInclude>`;

    const created = await call(`/sap/bc/adt/programs/includes${corrQuery}`, {
      method: "POST",
      // abap-adt-api uses a generic "application/*" for EVERY object-creation
      // POST regardless of type (no per-type content-type in its own
      // CreatableType table) - matching that verified value here rather than
      // guessing a specific vnd.sap.adt.* string for includes.
      headers: { "Content-Type": "application/*" },
      body: shell,
    });
    if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
    log.push(`Created shell ${name} in package ${packageName.toUpperCase()}${corrNr ? ` on ${corrNr}` : ""}.`);

    // 2) lock  3) put source  4) unlock — one stateful session
    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written (${source.split("\n").length} lines).`);
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    // Activate only after the edit lock is released.
    if (activate) {
      await runActivation(call, uri, name, log, "include");
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "create_cds",
  "Create a new CDS view (Data Definition / DDLS) in SAP and activate it. " +
  "Refuses to run on production profiles. Provide the complete CDS source " +
  "(e.g. 'define view entity <name> as select from ... { ... }'); the entity " +
  "name in the source must match cdsName. Needs a transport unless package is $TMP.",
  {
    cdsName: z.string().describe("CDS entity/DDLS name, e.g. ZKIT_I_PRODUCT. Must match the name in the source."),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete CDS DDL source (define view entity <name> as select from ... { ... })"),
    transport: z.string().optional().describe("Transport request, e.g. ABLK900123. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ cdsName, description, packageName, source, transport: corrNr, activate }) => {
    const name = cdsName.toUpperCase();
    // Content type is the UNVERSIONED one; the .v2 variant returns 415.
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<ddl:ddlSource xmlns:ddl="http://www.sap.com/adt/ddic/ddlsources" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="DDLS/DF" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</ddl:ddlSource>`;
    const text = await createSourceObject({
      name,
      uri: `/sap/bc/adt/ddic/ddl/sources/${cdsName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/ddic/ddl/sources",
      contentType: "application/vnd.sap.adt.ddlSource+xml",
      shell, source, corrNr, activate, kind: "CDS view",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "create_srvd",
  "Create a new Service Definition (SRVD) in SAP and activate it. Refuses to run on " +
  "production profiles. Provide the complete source (e.g. 'define service <name> " +
  "{ expose <entity>; }'); the service name must match srvdName. Needs a transport " +
  "unless package is $TMP.",
  {
    srvdName: z.string().describe("Service definition name, e.g. ZKIT_UI_PRODUCT. Must match the name in the source."),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete SRVD source (define service <name> { expose <entity>; })"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ srvdName, description, packageName, source, transport: corrNr, activate }) => {
    const name = srvdName.toUpperCase();
    // srvd:srvdSourceType="S" (Definition) is required, else create 400s.
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<srvd:srvdSource xmlns:srvd="http://www.sap.com/adt/ddic/srvdsources" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" srvd:srvdSourceType="S" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="SRVD/SRV" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</srvd:srvdSource>`;
    const text = await createSourceObject({
      name,
      uri: `/sap/bc/adt/ddic/srvd/sources/${srvdName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/ddic/srvd/sources",
      contentType: "application/vnd.sap.adt.ddic.srvd.v1+xml",
      shell, source, corrNr, activate, kind: "service definition",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "create_bdef",
  "Create a new Behavior Definition (BDEF) in SAP and activate it. Refuses to run on " +
  "production profiles. bdefName must equal the root entity the behavior is for, and " +
  "that entity must already exist. Provide the complete source (e.g. 'managed " +
  "implementation in class <cls> unique; define behavior for <entity> ... { ... }'). " +
  "A managed BDEF needs its persistent table + implementation class to exist for " +
  "activation to succeed. Needs a transport unless package is $TMP.",
  {
    bdefName: z.string().describe("Behavior definition name = the root entity it is defined for, e.g. ZKIT_R_PRODUCT."),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete BDEF source (define behavior for <entity> ... { ... })"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ bdefName, description, packageName, source, transport: corrNr, activate }) => {
    const name = bdefName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<blue:blueSource xmlns:blue="http://www.sap.com/wbobj/blue" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="BDEF/BDO" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</blue:blueSource>`;
    const text = await createSourceObject({
      name,
      uri: `/sap/bc/adt/bo/behaviordefinitions/${bdefName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/bo/behaviordefinitions",
      contentType: "application/vnd.sap.adt.blues.v1+xml",
      shell, source, corrNr, activate, kind: "behavior definition",
    });
    return { content: [{ type: "text", text }] };
  }
);

// --- access control / DCL (DCLS/DL) - source-based, same shape as CDS/SRVD/BDEF ---
// Verified live against a real system: reads as <dcl:dclSource abapsource:sourceUri=
// "source/main" ...>, i.e. a genuine text source exactly like CDS/SRVD/BDEF, not an
// XML-only object like domain/message class.

const dclUri = n => `/sap/bc/adt/acm/dcl/sources/${n.toLowerCase()}`;

server.tool(
  "create_dcl",
  "Create a new Access Control / DCL source (DCLS) for a CDS view and activate it. Refuses to run on " +
  "production profiles. Provide the complete DCL source, e.g. \"define role <name> { grant select on " +
  "<cds view> where (<field>) = aspect pfcg_auth(<auth object>, <auth field>, ACTVT = '03'); }\" - the role " +
  "name must match dclName. Needs a transport unless package is $TMP.",
  {
    dclName: z.string().describe("DCL/access control name, e.g. ZAC_MY_ENTITY. Must match the role name in the source."),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete DCL source (define role <name> { grant select on ... ; })"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ dclName, description, packageName, source, transport: corrNr, activate }) => {
    const name = dclName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<dcl:dclSource xmlns:dcl="http://www.sap.com/adt/acm/dclsources" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="DCLS/DL" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</dcl:dclSource>`;
    const text = await createSourceObject({
      name, uri: dclUri(dclName),
      createEndpoint: "/sap/bc/adt/acm/dcl/sources",
      contentType: "application/vnd.sap.adt.dclSource+xml",
      shell, source, corrNr, activate, kind: "access control",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_dcl",
  "Overwrite the source of an EXISTING Access Control / DCL source. REPLACES the whole definition - read it " +
  "first and send the complete result back. Refuses to run on production profiles. Prefer patch_dcl for small edits.",
  {
    dclName: z.string().describe("DCL/access control name, e.g. ZAC_MY_ENTITY"),
    source: z.string().describe("Complete new DCL source - REPLACES the entire definition"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ dclName, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: dclName.toUpperCase(), uri: dclUri(dclName),
      transform: wholeSource(source), corrNr, activate, kind: "access control", createHint: "create_dcl",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_dcl",
  "Modify PART of an existing Access Control / DCL source (e.g. change one condition). Replaces oldString " +
  "with newString (must match EXACTLY ONCE). Refuses to run on production profiles.",
  {
    dclName: z.string().describe("DCL/access control name, e.g. ZAC_MY_ENTITY"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ dclName, oldString, newString, transport: corrNr, activate }) => {
    const name = dclName.toUpperCase();
    const text = await editSourceObject({
      name, uri: dclUri(dclName),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "access control", createHint: "create_dcl",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "create_table",
  "Create a new DDIC transparent table (TABL) in SAP and activate it. Refuses to run " +
  "on production profiles. Provide the complete DDL source (define table <name> { ... }) " +
  "INCLUDING the standard annotations (@AbapCatalog.tableCategory : #TRANSPARENT, " +
  "@AbapCatalog.deliveryClass, @AbapCatalog.dataMaintenance), else the source is rejected. " +
  "The table name in the source must match tableName. Needs a transport unless package is $TMP.",
  {
    tableName: z.string().describe("Table name, e.g. ZKIT_PRODUCT. Must match the name in the source."),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete DDL (define table <name> { key ...; ... }) with @AbapCatalog annotations."),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ tableName, description, packageName, source, transport: corrNr, activate }) => {
    const name = tableName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<blue:blueSource xmlns:blue="http://www.sap.com/wbobj/blue" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="TABL/DT" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</blue:blueSource>`;
    const text = await createSourceObject({
      name,
      uri: `/sap/bc/adt/ddic/tables/${tableName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/ddic/tables",
      contentType: "application/vnd.sap.adt.tables.v2+xml",
      shell, source, corrNr, activate, kind: "table",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "create_srvb",
  "Create a Service Binding (SRVB) that exposes a service definition as an OData service, " +
  "then activate and publish it. Refuses to run on production profiles. The service " +
  "definition must already exist and be active. Publishing may require a transport on " +
  "clients set to auto-record; if it can't publish, the binding is still created and active.",
  {
    srvbName: z.string().describe("Service binding name, e.g. ZKIT_UI_PRODUCT_O4."),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    serviceDefinition: z.string().describe("Name of the service definition (SRVD) to bind, e.g. ZKIT_UI_PRODUCT."),
    odataVersion: z.enum(["V4", "V2"]).optional().default("V4").describe("OData protocol version (default V4)."),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate the binding after creating it."),
    publish: z.boolean().optional().default(true).describe("Publish the OData service after activating."),
  },
  async ({ srvbName, description, packageName, serviceDefinition, odataVersion, transport: corrNr, activate, publish }) => {
    assertWritable();

    const name = srvbName.toUpperCase();
    const srvdName = serviceDefinition.toUpperCase();
    const srvdUri = `/sap/bc/adt/ddic/srvd/sources/${serviceDefinition.toLowerCase()}`;
    const uri = `/sap/bc/adt/businessservices/bindings/${srvbName.toLowerCase()}`;
    const odataColl = odataVersion === "V2" ? "odatav2" : "odatav4";
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    // 1) create the binding: one POST of the full config referencing the SRVD
    const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
    const cfg =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<srvb:serviceBinding srvb:releaseSupported="false" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="SRVB/SVB" adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN" ` +
      `xmlns:srvb="http://www.sap.com/adt/ddic/ServiceBindings" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `  <srvb:services srvb:name="${escapeXml(name)}">\n` +
      `    <srvb:content srvb:version="0001" srvb:releaseState="NOT_RELEASED">\n` +
      `      <srvb:serviceDefinition adtcore:uri="${srvdUri}" adtcore:type="SRVD/SRV" adtcore:name="${escapeXml(srvdName)}"/>\n` +
      `      <srvb:bindingTypeData><adtcore:content adtcore:encoding="base64"/></srvb:bindingTypeData>\n` +
      `    </srvb:content>\n` +
      `  </srvb:services>\n` +
      `  <srvb:binding srvb:type="ODATA" srvb:version="${odataVersion}" srvb:category="0">\n` +
      `    <srvb:implementation adtcore:name="${escapeXml(name)}"/>\n` +
      `  </srvb:binding>\n` +
      `</srvb:serviceBinding>`;

    const created = await call(`/sap/bc/adt/businessservices/bindings${corrQuery}`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.sap.adt.businessservices.servicebinding.v2+xml" },
      body: cfg,
    });
    if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
    log.push(`Created service binding ${name} (OData ${odataVersion}) for service definition ${srvdName}.`);

    // 2) activate (service bindings have no source PUT/lock - just activate)
    if (activate) {
      await runActivation(call, uri, name, log, "service binding");
    }

    // 3) publish the OData service. Endpoint wants an objectReferences body and
    //    Accept: application/vnd.sap.as+xml; it returns an asx result envelope.
    if (publish) {
      const pubBody =
        `<?xml version="1.0" encoding="UTF-8"?>\n` +
        `<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">\n` +
        `  <adtcore:objectReference adtcore:uri="${uri}" adtcore:name="${escapeXml(name)}"/>\n` +
        `</adtcore:objectReferences>`;
      const pr = await call(`/sap/bc/adt/businessservices/${odataColl}/publishjobs${corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : ""}`, {
        method: "POST",
        headers: { "Content-Type": `application/vnd.sap.adt.businessservices.${odataColl}.v1+xml` },
        accept: "application/vnd.sap.as+xml",
        body: pubBody,
      });
      const sev = (pr.text.match(/<SEVERITY>([^<]*)<\/SEVERITY>/) || [])[1] || "";
      const shortText = (pr.text.match(/<SHORT_TEXT>([^<]*)<\/SHORT_TEXT>/) || [])[1] || "";
      const longText = (pr.text.match(/<LONG_TEXT>([^<]*)<\/LONG_TEXT>/) || [])[1] || "";
      if (!pr.ok || /ERROR|ABORT/i.test(sev)) {
        log.push(`Publish did NOT complete (HTTP ${pr.status}${sev ? `, ${sev}` : ""}): ${shortText || pr.text.slice(0, 300)}${longText ? ` - ${longText}` : ""}`);
        log.push("  The binding is created and active; publishing often needs a transport request on auto-record clients.");
      } else {
        log.push("Published - the OData service is now available.");
      }
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

// Shell-only create for ADT objects whose definition lives in XML rather than
// a text source (domain, data element). Create -> optionally activate.
async function createXmlObject({ name, uri, createEndpoint, contentType, shell, corrNr, activate, kind }) {
  assertWritable();
  const host = profile().host;
  const log = [];

  const { token, cookies: initialCookies } = await fetchCsrfToken();
  let cookies = initialCookies;
  if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

  const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
    const res = await fetch(`${host}${path}`, {
      method,
      headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
      body,
      agent,
    });
    cookies = mergeCookies(cookies, res);
    return { ok: res.ok, status: res.status, text: await res.text() };
  };

  const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
  const created = await call(`${createEndpoint}${corrQuery}`, {
    method: "POST",
    headers: { "Content-Type": contentType },
    body: shell,
  });
  if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
  log.push(`Created ${kind} ${name}${corrNr ? ` on ${corrNr}` : ""}.`);

  if (activate) await runActivation(call, uri, name, log, kind);
  else log.push("Not activated (activate=false) - activate it with activate_object.");

  return log.join("\n");
}

// Shared edit flow for ADT XML-content objects (domain, data element, table
// type, ...) - same lock/PUT/unlock/activate shape as editSourceObject, but
// there is no /source/main: the whole object's own URI IS the read/write
// resource (confirmed via the ADT discovery document's {?corrNr,lockHandle,
// version,accessMode,_action} template on these objects' base collection).
async function editXmlObject({ name, uri, transform, contentType, corrNr, activate, kind, createHint }) {
  assertWritable();
  const host = profile().host;
  const log = [];

  const { token, cookies: initialCookies } = await fetchCsrfToken();
  let cookies = initialCookies;
  if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

  const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
    const res = await fetch(`${host}${path}`, {
      method,
      headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
      body,
      agent,
    });
    cookies = mergeCookies(cookies, res);
    return { ok: res.ok, status: res.status, text: await res.text() };
  };

  const probe = await call(uri, { method: "GET", accept: "*/*" });
  if (probe.status === 404) throw new Error(`${kind} ${name} not found. Use ${createHint} to create a new one.`);
  if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);

  const before = String(probe.text).replace(/\r\n/g, "\n");
  const after = transform(before, log);
  log.push(`Target: ${uri}`);

  const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
    method: "POST",
    accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
  });
  if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
  const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
  if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
  log.push("Locked.");

  let wrote = false;
  try {
    const put = await call(
      `${uri}?lockHandle=${encodeURIComponent(handle)}` +
      (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
      { method: "PUT", headers: { "Content-Type": contentType }, body: after }
    );
    if (!put.ok) throw new Error(`PUT failed (${put.status}). ${put.text}`);
    log.push(`Written${corrNr ? ` on ${corrNr}` : ""}.`);
    wrote = true;
  } finally {
    const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
      method: "POST",
    });
    log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
  }

  if (wrote && activate) await runActivation(call, uri, name, log, kind);
  else if (wrote) log.push(`Not activated (activate=false) - activate it yourself or with activate_object.`);

  return log.join("\n");
}

// --- structures (TABL/DS) - DDL source, same shape as tables ---------------

const structureUri = n => `/sap/bc/adt/ddic/structures/${n.toLowerCase()}`;

server.tool(
  "create_structure",
  "Create a new DDIC structure (TABL/DS) from DDL source and optionally activate it. Refuses to run on " +
  "production profiles. Source looks like: define structure zst_foo { field : abap.char(10); }",
  {
    structureName: z.string().describe("Structure name, e.g. ZST_PLANT_EMAIL"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete DDL source (define structure <name> { ... })"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ structureName, description, packageName, source, transport: corrNr, activate }) => {
    const name = structureName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<blue:blueSource xmlns:blue="http://www.sap.com/wbobj/blue" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="TABL/DS" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</blue:blueSource>`;
    const text = await createSourceObject({
      name, uri: structureUri(structureName),
      createEndpoint: "/sap/bc/adt/ddic/structures",
      contentType: "application/vnd.sap.adt.structures.v2+xml",
      shell, source, corrNr, activate, kind: "structure",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_structure",
  "Overwrite the DDL source of an EXISTING DDIC structure. REPLACES the whole definition - read it first and " +
  "send the complete result back. Refuses to run on production profiles. Prefer patch_structure for small edits.",
  {
    structureName: z.string().describe("Structure name, e.g. ZST_PLANT_EMAIL"),
    source: z.string().describe("Complete new DDL source - REPLACES the entire structure"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - a structure change may affect users of it."),
  },
  async ({ structureName, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: structureName.toUpperCase(), uri: structureUri(structureName),
      transform: wholeSource(source), corrNr, activate, kind: "structure", createHint: "create_structure",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_structure",
  "Modify PART of an existing DDIC structure's DDL (e.g. add one field). Replaces oldString with newString " +
  "(must match EXACTLY ONCE). Refuses to run on production profiles.",
  {
    structureName: z.string().describe("Structure name, e.g. ZST_PLANT_EMAIL"),
    oldString: z.string().describe("Exact existing DDL text to replace. Must occur exactly once."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ structureName, oldString, newString, transport: corrNr, activate }) => {
    const name = structureName.toUpperCase();
    const text = await editSourceObject({
      name, uri: structureUri(structureName),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "structure", createHint: "create_structure",
    });
    return { content: [{ type: "text", text }] };
  }
);

// --- interfaces (INTF/OI) - ABAP source, same shape as classes -------------

const interfaceUri = n => `/sap/bc/adt/oo/interfaces/${n.toLowerCase()}`;

server.tool(
  "create_interface",
  "Create a new ABAP interface and optionally activate it. Refuses to run on production profiles. Needs the " +
  "full source (INTERFACE <name> PUBLIC. ... ENDINTERFACE.).",
  {
    interfaceName: z.string().describe("Interface name, e.g. ZIF_ABL_PLANT_EMAIL"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete ABAP source of the interface"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ interfaceName, description, packageName, source, transport: corrNr, activate }) => {
    const name = interfaceName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<intf:abapInterface xmlns:intf="http://www.sap.com/adt/oo/interfaces" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="INTF/OI" ` +
      `adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</intf:abapInterface>`;
    const text = await createSourceObject({
      name, uri: interfaceUri(interfaceName),
      createEndpoint: "/sap/bc/adt/oo/interfaces",
      contentType: "application/vnd.sap.adt.oo.interfaces.v5+xml",
      shell, source, corrNr, activate, kind: "interface",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_interface",
  "Overwrite the source of an EXISTING ABAP interface. REPLACES the whole interface - read it first and send " +
  "the complete result back. Refuses to run on production profiles. Prefer patch_interface for small edits.",
  {
    interfaceName: z.string().describe("Interface name, e.g. ZIF_ABL_PLANT_EMAIL"),
    source: z.string().describe("Complete new ABAP source - REPLACES the entire interface"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ interfaceName, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: interfaceName.toUpperCase(), uri: interfaceUri(interfaceName),
      transform: wholeSource(source), corrNr, activate, kind: "interface", createHint: "create_interface",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_interface",
  "Modify PART of an existing ABAP interface (e.g. add one method signature). Replaces oldString with " +
  "newString (must match EXACTLY ONCE). Refuses to run on production profiles.",
  {
    interfaceName: z.string().describe("Interface name, e.g. ZIF_ABL_PLANT_EMAIL"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ interfaceName, oldString, newString, transport: corrNr, activate }) => {
    const name = interfaceName.toUpperCase();
    const text = await editSourceObject({
      name, uri: interfaceUri(interfaceName),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "interface", createHint: "create_interface",
    });
    return { content: [{ type: "text", text }] };
  }
);

// --- metadata extensions (DDLX/EX) - UI annotations for a CDS view ---------

const ddlxUri = n => `/sap/bc/adt/ddic/ddlx/sources/${n.toLowerCase()}`;

server.tool(
  "create_ddlx",
  "Create a new CDS metadata extension (DDLX) - the object that carries UI annotations for a CDS view, which a " +
  "Fiori Elements app needs. Refuses to run on production profiles. Source looks like: " +
  "@Metadata.layer: #CORE annotate view ZI_FOO with { @UI.lineItem: [{position: 10}] field; }",
  {
    ddlxName: z.string().describe("Metadata extension name, e.g. ZTJI_PLANT_EMAIL_MDE"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    source: z.string().describe("Complete DDLX source (@Metadata.layer: ... annotate view ... with { ... })"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing the source"),
  },
  async ({ ddlxName, description, packageName, source, transport: corrNr, activate }) => {
    const name = ddlxName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<ddlx:ddlxSource xmlns:ddlx="http://www.sap.com/adt/ddic/ddlxsources" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="DDLX/EX" adtcore:language="EN" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</ddlx:ddlxSource>`;
    const text = await createSourceObject({
      name, uri: ddlxUri(ddlxName),
      createEndpoint: "/sap/bc/adt/ddic/ddlx/sources",
      contentType: "application/vnd.sap.adt.ddic.ddlx.v1+xml",
      shell, source, corrNr, activate, kind: "metadata extension",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_ddlx",
  "Overwrite the source of an EXISTING CDS metadata extension (DDLX). REPLACES the whole source. Refuses to " +
  "run on production profiles. Prefer patch_ddlx for small edits.",
  {
    ddlxName: z.string().describe("Metadata extension name"),
    source: z.string().describe("Complete new DDLX source - REPLACES the entire object"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ ddlxName, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: ddlxName.toUpperCase(), uri: ddlxUri(ddlxName),
      transform: wholeSource(source), corrNr, activate, kind: "metadata extension", createHint: "create_ddlx",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_ddlx",
  "Modify PART of an existing CDS metadata extension (e.g. add one @UI annotation). Replaces oldString with " +
  "newString (must match EXACTLY ONCE). Refuses to run on production profiles.",
  {
    ddlxName: z.string().describe("Metadata extension name"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ ddlxName, oldString, newString, transport: corrNr, activate }) => {
    const name = ddlxName.toUpperCase();
    const text = await editSourceObject({
      name, uri: ddlxUri(ddlxName),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "metadata extension", createHint: "create_ddlx",
    });
    return { content: [{ type: "text", text }] };
  }
);

// --- domains + data elements (XML-defined, no text source) -----------------

// ADT writes DDIC lengths as zero-padded 6-digit strings.
const pad6 = n => String(Math.max(0, parseInt(n, 10) || 0)).padStart(6, "0");

server.tool(
  "create_domain",
  "Create a new DDIC domain (DOMA/DD) and optionally activate it. A domain defines the technical type " +
  "(datatype/length/decimals) and optional fixed values. Refuses to run on production profiles.",
  {
    domainName: z.string().describe("Domain name, e.g. ZDOM_PLANT"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    datatype: z.string().describe("DDIC data type, e.g. CHAR, NUMC, DEC, DATS, TIMS, INT4, STRING"),
    length: z.number().describe("Field length, e.g. 10"),
    decimals: z.number().optional().default(0).describe("Decimal places (for DEC/QUAN/CURR)"),
    lowercase: z.boolean().optional().default(false).describe("Allow lower case"),
    fixedValues: z.array(z.object({ value: z.string(), description: z.string() })).optional()
      .describe("Optional fixed value list, e.g. [{value:'X',description:'Yes'}]"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after creating"),
  },
  async ({ domainName, description, packageName, datatype, length, decimals, lowercase, fixedValues, transport: corrNr, activate }) => {
    const name = domainName.toUpperCase();
    const fixed = (fixedValues || []).length
      ? `<doma:fixValues>` + fixedValues.map(v =>
          `<doma:fixValue><doma:low>${escapeXml(v.value)}</doma:low><doma:description>${escapeXml(v.description)}</doma:description></doma:fixValue>`
        ).join("") + `</doma:fixValues>`
      : `<doma:fixValues/>`;
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<doma:domain xmlns:doma="http://www.sap.com/dictionary/domain" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="DOMA/DD" ` +
      `adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">` +
      `<adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>` +
      `<doma:content>` +
      `<doma:typeInformation><doma:datatype>${escapeXml(datatype.toUpperCase())}</doma:datatype>` +
      `<doma:length>${pad6(length)}</doma:length><doma:decimals>${pad6(decimals)}</doma:decimals></doma:typeInformation>` +
      `<doma:outputInformation><doma:length>${pad6(length)}</doma:length><doma:style>00</doma:style>` +
      `<doma:conversionExit/><doma:signExists>false</doma:signExists>` +
      `<doma:lowercase>${lowercase ? "true" : "false"}</doma:lowercase><doma:ampmFormat>false</doma:ampmFormat></doma:outputInformation>` +
      `<doma:valueInformation><doma:appendExists>false</doma:appendExists>${fixed}</doma:valueInformation>` +
      `</doma:content></doma:domain>`;
    const text = await createXmlObject({
      name, uri: `/sap/bc/adt/ddic/domains/${domainName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/ddic/domains",
      contentType: "application/vnd.sap.adt.domains.v2+xml",
      shell, corrNr, activate, kind: "domain",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "create_data_element",
  "Create a new DDIC data element (DTEL/DE) and optionally activate it. Either point it at a domain " +
  "(typeKind='domain', typeName=<domain>) or give a built-in type (typeKind='predefinedAbapType' with " +
  "dataType/length). Field labels are what users see on screens. Refuses to run on production profiles.",
  {
    dataElementName: z.string().describe("Data element name, e.g. ZDE_PLANT"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    typeKind: z.enum(["domain", "predefinedAbapType"]).optional().default("domain")
      .describe("'domain' to reference a domain, or 'predefinedAbapType' for a built-in type"),
    typeName: z.string().optional().describe("Domain name when typeKind='domain', e.g. ZDOM_PLANT"),
    dataType: z.string().optional().describe("DDIC type when typeKind='predefinedAbapType', e.g. CHAR"),
    length: z.number().optional().describe("Length when typeKind='predefinedAbapType'"),
    decimals: z.number().optional().default(0).describe("Decimals when typeKind='predefinedAbapType'"),
    shortLabel: z.string().optional().describe("Short field label (max 10 chars)"),
    mediumLabel: z.string().optional().describe("Medium field label (max 20 chars)"),
    longLabel: z.string().optional().describe("Long field label (max 40 chars)"),
    headingLabel: z.string().optional().describe("Heading field label (max 55 chars)"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after creating"),
  },
  async (a) => {
    const name = a.dataElementName.toUpperCase();
    if (a.typeKind === "domain" && !a.typeName) throw new Error("typeName (the domain) is required when typeKind='domain'.");
    if (a.typeKind === "predefinedAbapType" && !a.dataType) throw new Error("dataType is required when typeKind='predefinedAbapType'.");

    // SAP's fixed maxima for the four field labels.
    const MAX = { short: 10, medium: 20, long: 40, heading: 55 };
    const short = (a.shortLabel || a.description).slice(0, MAX.short);
    const medium = (a.mediumLabel || a.description).slice(0, MAX.medium);
    const long = (a.longLabel || a.description).slice(0, MAX.long);
    const heading = (a.headingLabel || short).slice(0, MAX.heading);

    // ADT wants the technical type spelled out even when the element points at a
    // domain, so read it off the domain rather than making the caller repeat it.
    let dataType = (a.dataType || "").toUpperCase();
    let length = a.length;
    let decimals = a.decimals;
    if (a.typeKind === "domain") {
      try {
        const dom = await adtGet(`/sap/bc/adt/ddic/domains/${a.typeName.toLowerCase()}`, "*/*");
        dataType = (dom.match(/<doma:datatype>([^<]*)</) || [])[1] || dataType;
        length = Number((dom.match(/<doma:length>(\d+)</) || [])[1] ?? length ?? 0);
        decimals = Number((dom.match(/<doma:decimals>(\d+)</) || [])[1] ?? decimals ?? 0);
      } catch {
        if (!dataType) throw new Error(
          `Could not read domain ${a.typeName} to determine its type. Check the name, or pass dataType/length explicitly.`);
      }
    }

    const typeBits =
      (a.typeKind === "domain"
        ? `<dtel:typeKind>domain</dtel:typeKind><dtel:typeName>${escapeXml(a.typeName.toUpperCase())}</dtel:typeName>`
        : `<dtel:typeKind>predefinedAbapType</dtel:typeKind>`) +
      `<dtel:dataType>${escapeXml(dataType)}</dtel:dataType>` +
      `<dtel:dataTypeLength>${pad6(length)}</dtel:dataTypeLength>` +
      `<dtel:dataTypeDecimals>${pad6(decimals)}</dtel:dataTypeDecimals>`;

    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<blue:wbobj xmlns:blue="http://www.sap.com/wbobj/dictionary/dtel" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="DTEL/DE" ` +
      `adtcore:description="${escapeXml(a.description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">` +
      `<adtcore:packageRef adtcore:name="${escapeXml(a.packageName.toUpperCase())}"/>` +
      `<dtel:dataElement xmlns:dtel="http://www.sap.com/adt/dictionary/dataelements">` +
      typeBits +
      `<dtel:shortFieldLabel>${escapeXml(short)}</dtel:shortFieldLabel>` +
      `<dtel:shortFieldLength>${short.length}</dtel:shortFieldLength>` +
      `<dtel:shortFieldMaxLength>${MAX.short}</dtel:shortFieldMaxLength>` +
      `<dtel:mediumFieldLabel>${escapeXml(medium)}</dtel:mediumFieldLabel>` +
      `<dtel:mediumFieldLength>${medium.length}</dtel:mediumFieldLength>` +
      `<dtel:mediumFieldMaxLength>${MAX.medium}</dtel:mediumFieldMaxLength>` +
      `<dtel:longFieldLabel>${escapeXml(long)}</dtel:longFieldLabel>` +
      `<dtel:longFieldLength>${long.length}</dtel:longFieldLength>` +
      `<dtel:longFieldMaxLength>${MAX.long}</dtel:longFieldMaxLength>` +
      `<dtel:headingFieldLabel>${escapeXml(heading)}</dtel:headingFieldLabel>` +
      `<dtel:headingFieldLength>${heading.length}</dtel:headingFieldLength>` +
      `<dtel:headingFieldMaxLength>${MAX.heading}</dtel:headingFieldMaxLength>` +
      // ADT's schema is a strict sequence - these trailing elements are required
      // even when empty (verified against a standard data element).
      `<dtel:searchHelp/><dtel:searchHelpParameter/><dtel:setGetParameter/><dtel:defaultComponentName/>` +
      `<dtel:deactivateInputHistory>false</dtel:deactivateInputHistory>` +
      `<dtel:changeDocument>false</dtel:changeDocument>` +
      `<dtel:leftToRightDirection>false</dtel:leftToRightDirection>` +
      `<dtel:deactivateBIDIFiltering>false</dtel:deactivateBIDIFiltering>` +
      `</dtel:dataElement></blue:wbobj>`;

    const text = await createXmlObject({
      name, uri: `/sap/bc/adt/ddic/dataelements/${a.dataElementName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/ddic/dataelements",
      contentType: "application/vnd.sap.adt.dataelements.v2+xml",
      shell, corrNr: a.transport, activate: a.activate, kind: "data element",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "create_table_type",
  "Create a new DDIC table type (TTYP/DA) - the ABAP type for an internal table - and optionally activate it. " +
  "Point it at a dictionary type (structure/data element/table) with rowTypeKind='dictionaryType' and " +
  "rowTypeName, or at a built-in type with rowTypeKind='predefinedAbapType' plus dataType/length. " +
  "Refuses to run on production profiles.",
  {
    tableTypeName: z.string().describe("Table type name, e.g. ZTT_PLANT_EMAIL"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    rowTypeKind: z.enum(["dictionaryType", "predefinedAbapType"]).optional().default("dictionaryType")
      .describe("Where the row type comes from"),
    rowTypeName: z.string().optional().describe("Structure/data element/table name when rowTypeKind='dictionaryType', e.g. ZST_PLANT_EMAIL"),
    dataType: z.string().optional().describe("Built-in type when rowTypeKind='predefinedAbapType', e.g. STRING, CHAR"),
    length: z.number().optional().default(0).describe("Length for a built-in row type"),
    decimals: z.number().optional().default(0).describe("Decimals for a built-in row type"),
    accessType: z.enum(["standard", "sorted", "hashed", "index"]).optional().default("standard")
      .describe("Internal table access type"),
    keyKind: z.enum(["unique", "nonUnique", "notSpecified"]).optional().default("nonUnique")
      .describe("Primary key uniqueness"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after creating"),
  },
  async (a) => {
    const name = a.tableTypeName.toUpperCase();
    if (a.rowTypeKind === "dictionaryType" && !a.rowTypeName)
      throw new Error("rowTypeName is required when rowTypeKind='dictionaryType'.");
    if (a.rowTypeKind === "predefinedAbapType" && !a.dataType)
      throw new Error("dataType is required when rowTypeKind='predefinedAbapType'.");

    // ADT expects the whole rowType block even when half of it is empty.
    const rowType =
      `<ttyp:rowType><ttyp:typeKind>${a.rowTypeKind}</ttyp:typeKind>` +
      (a.rowTypeName ? `<ttyp:typeName>${escapeXml(a.rowTypeName.toUpperCase())}</ttyp:typeName>` : `<ttyp:typeName/>`) +
      `<ttyp:builtInType><ttyp:dataType>${escapeXml((a.dataType || "").toUpperCase())}</ttyp:dataType>` +
      `<ttyp:length>${pad6(a.length)}</ttyp:length><ttyp:decimals>${pad6(a.decimals)}</ttyp:decimals></ttyp:builtInType>` +
      `<ttyp:rangeType/></ttyp:rowType>`;

    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<ttyp:tableType xmlns:ttyp="http://www.sap.com/dictionary/tabletype" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="TTYP/DA" ` +
      `adtcore:description="${escapeXml(a.description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">` +
      `<adtcore:packageRef adtcore:name="${escapeXml(a.packageName.toUpperCase())}"/>` +
      rowType +
      `<ttyp:initialRowCount>00000</ttyp:initialRowCount>` +
      `<ttyp:accessType>${a.accessType}</ttyp:accessType>` +
      `<ttyp:primaryKey ttyp:isVisible="true" ttyp:isEditable="true">` +
      `<ttyp:definition>standard</ttyp:definition><ttyp:kind>${a.keyKind}</ttyp:kind>` +
      `<ttyp:components ttyp:isVisible="false"/><ttyp:alias/></ttyp:primaryKey>` +
      `<ttyp:secondaryKeys ttyp:isVisible="true" ttyp:isEditable="true">` +
      `<ttyp:allowed>notSpecified</ttyp:allowed></ttyp:secondaryKeys>` +
      `</ttyp:tableType>`;

    const text = await createXmlObject({
      name, uri: `/sap/bc/adt/ddic/tabletypes/${a.tableTypeName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/ddic/tabletypes",
      contentType: "application/vnd.sap.adt.tabletype.v1+xml",
      shell, corrNr: a.transport, activate: a.activate, kind: "table type",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_table_type",
  "Modify PART of an existing DDIC table type's XML definition (e.g. change accessType, keyKind, or the row " +
  "type). Replaces oldString with newString (must match EXACTLY ONCE) in the object's raw XML - read it first " +
  "with get_object_info to see the exact text to target. Refuses to run on production profiles.",
  {
    tableTypeName: z.string().describe("Table type name, e.g. ZTT_PLANT_EMAIL"),
    oldString: z.string().describe("Exact existing XML text to replace. Must occur exactly once."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ tableTypeName, oldString, newString, transport: corrNr, activate }) => {
    const name = tableTypeName.toUpperCase();
    const text = await editXmlObject({
      name, uri: `/sap/bc/adt/ddic/tabletypes/${tableTypeName.toLowerCase()}`,
      transform: replaceOnce(oldString, newString, name),
      contentType: "application/vnd.sap.adt.tabletype.v1+xml",
      corrNr, activate, kind: "table type", createHint: "create_table_type",
    });
    return { content: [{ type: "text", text }] };
  }
);

// --- message class (structured content, no text source) -------------------
// MSAG has no DDL-like text syntax (SE91 is a form editor) - the whole class,
// including its numbered messages, lives in one XML document at its own URI
// (no /source/main). Verified live against a real system: GET returns
// <mc:messageClass> with <mc:messages mc:msgno=".." mc:msgtext=".."> children,
// one per message. Shell creation mirrors the same createBodySimple shape
// abap-adt-api uses for this type (packageRef only, Content-Type application/*).

server.tool(
  "create_message_class",
  "Create a new empty Message Class (MSAG) and optionally activate it. A message class is a named container " +
  "for numbered messages (T100 texts) used by MESSAGE/RAISE statements and RAP failed/reported responses. " +
  "Creates the empty class only - add messages afterwards with patch_message_class. Refuses to run on " +
  "production profiles.",
  {
    messageClassName: z.string().describe("Message class name, e.g. ZCL_MY_MESSAGES (max 20 chars)"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after creating"),
  },
  async ({ messageClassName, description, packageName, transport: corrNr, activate }) => {
    const name = messageClassName.toUpperCase();
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<mc:messageClass xmlns:mc="http://www.sap.com/adt/MessageClass" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:name="${escapeXml(name)}" adtcore:type="MSAG/N" ` +
      `adtcore:description="${escapeXml(description)}" ` +
      `adtcore:language="EN" adtcore:masterLanguage="EN">` +
      `<adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>` +
      `</mc:messageClass>`;
    const text = await createXmlObject({
      name, uri: `/sap/bc/adt/messageclass/${messageClassName.toLowerCase()}`,
      createEndpoint: "/sap/bc/adt/messageclass",
      contentType: "application/*",
      shell, corrNr, activate, kind: "message class",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_message_class",
  "Add or update ONE numbered message (T100 text) in an existing Message Class, then optionally activate. " +
  "Writes directly to that message's own sub-resource - confirmed against the ADT discovery document " +
  "(/sap/bc/adt/messageclass/{name}/messages/{msgno}), the same endpoint the atom:link on a GET of the class " +
  "points to for each message. PUT is an upsert: works whether the number already exists or not. Use &1 &2 " +
  "&3 &4 in text as placeholders for MESSAGE ... WITH values. Refuses to run on production profiles.",
  {
    messageClassName: z.string().describe("Message class name, e.g. ZCL_MY_MESSAGES"),
    msgno: z.string().describe("Message number, e.g. '001' (zero-padded to 3 digits automatically)"),
    text: z.string().describe("Message text, max 73 chars. Use &1 &2 &3 &4 for placeholders."),
    selfExplanatory: z.boolean().optional().default(true).describe("Whether the message is self-explanatory (no long text needed)"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
    activate: z.boolean().optional().default(true).describe("Activate after writing"),
  },
  async ({ messageClassName, msgno, text: msgtext, selfExplanatory, transport: corrNr, activate }) => {
    assertWritable();
    const name = messageClassName.toUpperCase();
    const no = String(msgno).trim().padStart(3, "0");
    const uri = `/sap/bc/adt/messageclass/${messageClassName.toLowerCase()}`;
    const msgUri = `${uri}/messages/${no}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const probe = await call(uri, { method: "GET" });
    if (probe.status === 404) throw new Error(`Message class ${name} not found. Use create_message_class to create it first.`);
    if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    // The message element needs its own namespace declarations when sent
    // standalone (it's normally a child of <mc:messageClass>, which is where
    // a GET declares xmlns:mc/xmlns:adtcore).
    const body =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<mc:messages xmlns:mc="http://www.sap.com/adt/MessageClass" xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `mc:msgno="${no}" mc:msgtext="${escapeXml(msgtext)}" ` +
      `mc:selfexplainatory="${selfExplanatory ? "true" : "false"}" mc:documented="false" adtcore:name=""/>`;

    let wrote = false;
    try {
      const put = await call(
        `${msgUri}?lockHandle=${encodeURIComponent(handle)}` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "application/*" }, body }
      );
      if (!put.ok) throw new Error(`PUT failed (${put.status}). ${put.text}`);
      log.push(`Message ${no} written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, { method: "POST" });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    if (wrote && activate) await runActivation(call, uri, name, log, "message class");
    else if (wrote) log.push("Not activated (activate=false).");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

// --- transports -----------------------------------------------------------

server.tool(
  "list_transports",
  "List transport requests for a user (default: the profile's own user). Read-only and safe on any profile. " +
  "Use it to find an open request number to pass as `transport` to the create/update tools.",
  {
    user: z.string().optional().describe("SAP user name. Defaults to the current profile's user."),
    status: z.enum(["modifiable", "released", "all"]).optional().default("modifiable")
      .describe("Which requests to return. 'modifiable' = still open."),
  },
  async ({ user, status }) => {
    const p = profile();
    const who = (user || p.user || "").toUpperCase();
    const trstatus = status === "released" ? "R" : status === "all" ? "" : "D";
    const path = `/sap/bc/adt/cts/transportrequests?_action=FIND&trfunction=K` +
      (trstatus ? `&trstatus=${trstatus}` : "") + `&user=${encodeURIComponent(who)}`;
    const xml = await adtGet(path, "*/*");

    // SAP returns both the modifiable and released sections regardless of the
    // trstatus filter, so filter on each request's own status here.
    const all = [...xml.matchAll(/<tm:request\b([^>]*)>/g)].map(m => {
      const a = m[1];
      const g = (k) => (a.match(new RegExp(`tm:${k}="([^"]*)"`)) || [])[1] || "";
      return { number: g("number"), desc: decodeXml(g("desc")), owner: g("owner"), status: g("status"), type: g("type") };
    }).filter(r => r.number);

    const rows = status === "all" ? all
      : status === "released" ? all.filter(r => r.status === "R")
      : all.filter(r => r.status !== "R"); // modifiable = anything not released

    if (!rows.length) {
      const hint = status === "modifiable" && all.length
        ? ` (${all.length} released request(s) exist - pass status:"all" to see them)` : "";
      return { content: [{ type: "text", text: `No ${status} transport requests found for ${who}.${hint}` }] };
    }
    const label = s => (s === "R" ? "released" : s === "D" ? "modifiable" : s || "?");
    const lines = rows.map(r => `${r.number}  [${label(r.status)}]  ${r.desc}${r.owner && r.owner !== who ? `  (owner ${r.owner})` : ""}`);
    return { content: [{ type: "text", text: `Transport requests for ${who} (${status}):\n` + lines.join("\n") }] };
  }
);

// Pulls every tm:xxx="..." attribute out of one opening tag, generically -
// verified against the open-source abap-adt-api client's transportDetails()
// (GET /sap/bc/adt/cts/transportrequests/{tr}, media type
// application/vnd.sap.adt.transportorganizer.v1+xml): the response is a
// <tm:request> with tm:number/tm:desc/tm:owner/tm:status/tm:type attributes,
// nested <tm:task> elements with the same attribute shape, and
// <tm:abap_object tm:pgmid=".." tm:type=".." tm:name=".."/> entries for the
// objects registered under it. Reading attributes generically (rather than
// a fixed list) means an SAP-version field we haven't seen still shows up.
function tmAttrs(tagStr) {
  const out = {};
  for (const m of String(tagStr || "").matchAll(/tm:([\w-]+)="([^"]*)"/g)) out[m[1]] = decodeXml(m[2]);
  return out;
}

server.tool(
  "get_transport_details",
  "Inspect ONE transport request: its description/owner/status, its tasks (with their own owners/status), " +
  "and every ABAP object registered under it. Use this to see what a transport actually contains before " +
  "releasing it, or to check who owns which task. Read-only and safe on any profile.",
  {
    transport: z.string().describe("Transport request number, e.g. D01K900123"),
  },
  async ({ transport }) => {
    const tr = transport.toUpperCase();
    const xml = await adtGet(
      `/sap/bc/adt/cts/transportrequests/${encodeURIComponent(tr)}`,
      "application/vnd.sap.adt.transportorganizer.v1+xml"
    );

    const rootMatch = xml.match(/<tm:request\b([^>]*)>/) || xml.match(/<tm:request\b([^>]*)\/>/);
    if (!rootMatch) throw new Error(`Could not parse a transport request from the response for ${tr}. ${xml.slice(0, 500)}`);
    const root = tmAttrs(rootMatch[1]);

    const tasks = [...xml.matchAll(/<tm:task\b([^>]*)>/g)].map(m => tmAttrs(m[1]));

    // The same object shows up 2-3x (once loose under the request, again
    // inside <tm:all_objects>, again inside its owning <tm:task>) - confirmed
    // live. pgmid CORR entries are just "request released" log comments, not
    // real objects. Dedupe by pgmid+type+name and drop the CORR noise.
    const seen = new Set();
    const objects = [...xml.matchAll(/<tm:abap_object\b([^>]*)\/?>/g)]
      .map(m => tmAttrs(m[1]))
      .filter(o => o.pgmid !== "CORR")
      .filter(o => {
        const key = `${o.pgmid}|${o.type}|${o.name}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

    const log = [
      `${root.number || tr}  [${root.status_text || root.status || "?"}]${root.type ? `  type ${root.type}` : ""}`,
      `Description: ${root.desc || "(none)"}`,
      `Owner: ${root.owner || "?"}${root.target ? `   Target: ${root.target}${root.target_desc ? ` (${root.target_desc})` : ""}` : ""}`,
    ];
    if (tasks.length) {
      log.push(`\nTasks (${tasks.length}):`);
      for (const t of tasks) log.push(`  ${t.number}  [${t.status_text || t.status || "?"}]  owner ${t.owner || "?"}  "${t.desc || ""}"`);
    } else {
      log.push("\nTasks: none");
    }
    if (objects.length) {
      log.push(`\nObjects (${objects.length}):`);
      for (const o of objects) {
        const name = (o.name || "?").replace(/\s+/g, " ").trim();
        log.push(`  ${o.wbtype || o.type || "?"}  ${name}${o.obj_desc ? `  - ${o.obj_desc}` : ""}`);
      }
    } else {
      log.push("\nObjects: none registered yet.");
    }
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

// Extracts every LEAF element (a tag with no nested child elements) from an
// XML fragment as flat key/value pairs - deliberately schema-agnostic. The
// asx:abap/asx:values envelope this tool reads back from
// /sap/bc/adt/cts/transportchecks nests plain ABAP-structure field names
// (TRKORR, AS4TEXT, ...) that aren't documented anywhere public; grabbing
// every leaf rather than a hand-picked list means the real field names
// surface without having to guess them.
function leafFields(fragment) {
  const out = {};
  for (const m of String(fragment || "").matchAll(/<(\w+)>([^<]*)<\/\1>/g)) {
    if (!(m[1] in out)) out[m[1]] = decodeXml(m[2]);
  }
  return out;
}

server.tool(
  "check_transport_lock",
  "Check whether an object is ALREADY locked/registered in some other open transport request - the thing " +
  "that causes 'object is locked in request X' conflicts. Also lists which of your own open requests the " +
  "object could be assigned to. This is a dry-run check (verified against the ADT 'transportchecks' " +
  "endpoint abap-adt-api uses) - it changes nothing. Read-only and safe on any profile.",
  {
    objectUri: z.string().describe("ADT URI of the object, e.g. /sap/bc/adt/oo/classes/zcl_foo"),
    devclass: z.string().optional().describe("The object's package (dev class), e.g. ZHRY_ABAP_PP. Needed to find candidate requests; omit if you only care about existing locks."),
    operation: z.enum(["I", "U", "D"]).optional().default("U")
      .describe("I = as if inserting a new object, U = as if updating an existing one (default), D = as if deleting it."),
  },
  async ({ objectUri, devclass, operation }) => {
    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const mediaType = "application/vnd.sap.as+xml; charset=UTF-8; dataname=com.sap.adt.transport.service.checkData";
    const body =
      `<?xml version="1.0" encoding="UTF-8"?><asx:abap xmlns:asx="http://www.sap.com/abapxml" version="1.0">\n` +
      `  <asx:values>\n` +
      `    <DATA>\n` +
      `      <DEVCLASS>${escapeXml(devclass || "")}</DEVCLASS>\n` +
      `      <OPERATION>${escapeXml(operation)}</OPERATION>\n` +
      `      <URI>${escapeXml(objectUri)}</URI>\n` +
      `    </DATA>\n` +
      `  </asx:values>\n` +
      `</asx:abap>`;

    const res = await fetch(`${profile().host}/sap/bc/adt/cts/transportchecks`, {
      method: "POST",
      headers: { ...authHeaders(mediaType), "X-CSRF-Token": token, "Content-Type": mediaType, Cookie: cookies },
      body,
      agent,
    });
    cookies = mergeCookies(cookies, res);
    const text = await res.text();
    if (!res.ok) throw new Error(`Transport check failed (${res.status}). ${text}`);

    const dataBlock = (text.match(/<DATA>([\s\S]*)<\/DATA>/) || [])[1] || text;

    const lockBlock = (dataBlock.match(/<LOCKS>([\s\S]*?)<\/LOCKS>/) || [])[1] || "";
    const holderHeader = (lockBlock.match(/<REQ_HEADER>([\s\S]*?)<\/REQ_HEADER>/) || [])[1] || "";
    const holder = leafFields(holderHeader);

    const requestBlocks = [...dataBlock.matchAll(/<CTS_REQUEST>([\s\S]*?)<\/CTS_REQUEST>/g)];
    const candidates = requestBlocks.map(m => {
      const header = (m[1].match(/<REQ_HEADER>([\s\S]*?)<\/REQ_HEADER>/) || [])[1] || "";
      return leafFields(header);
    });

    const messageBlocks = [...dataBlock.matchAll(/<CTS_MESSAGE>([\s\S]*?)<\/CTS_MESSAGE>/g)];
    const messages = messageBlocks.map(m => leafFields(m[1]));

    // REQ_HEADER field names (TRKORR, TRSTATUS, TARSYSTEM, AS4USER, AS4TEXT, ...)
    // confirmed live against a real system - this is the plain CTS request-
    // header structure, not documented in the ADT REST docs.
    const label = (s) => (s === "R" ? "released" : s === "D" ? "modifiable" : s || "?");
    const reqLine = (r) =>
      `${r.TRKORR || "?"}  [${label(r.TRSTATUS)}]  ${r.AS4TEXT || ""}` +
      `${r.AS4USER ? `  (owner ${r.AS4USER})` : ""}${r.TARSYSTEM ? `  target ${r.TARSYSTEM}` : ""}`;
    const fmt = (f) => Object.entries(f).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join("  ");

    const log = [`Transport check for ${objectUri} (operation ${operation})`];
    if (holder.TRKORR) {
      log.push(`\nLOCKED in an existing request:`);
      log.push(`  ${reqLine(holder)}`);
    } else {
      log.push(`\nNot currently locked by any other request.`);
    }
    if (candidates.length) {
      const MAX = 15;
      log.push(`\nCandidate request(s) you could assign it to (${candidates.length}):`);
      for (const c of candidates.slice(0, MAX)) log.push(`  ${reqLine(c)}`);
      if (candidates.length > MAX) log.push(`  ... and ${candidates.length - MAX} more.`);
    }
    if (messages.length) {
      log.push(`\nMessages:`);
      for (const m of messages) log.push(`  ${fmt(m)}`);
    }
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "create_transport",
  "Create a NEW transport request (a workbench request, CTS type K) for a package - the write counterpart " +
  "to list_transports/get_transport_details. Use this when list_transports found no suitable open request " +
  "and an object needs a request number before it can be created/updated. Refuses to run on production/" +
  "read-only profiles. Returns the new request number, ready to pass as `transport` to the create/update " +
  "tools.",
  {
    devclass: z.string().describe("Package (dev class) this transport is for, e.g. ZHRY_ABAP_PP. Must be a real transportable package - $TMP objects never need a transport."),
    description: z.string().describe("Short description for the transport request (shown in SE09/SE10)."),
    transportLayer: z.string().optional().describe("Transport layer override. Normally omit - SAP derives it from the package."),
  },
  async ({ devclass, description, transportLayer }) => {
    assertWritable();
    const dc = devclass.toUpperCase();
    if (dc === "$TMP") throw new Error("$TMP is a local package and never needs a transport - omit `transport` entirely for $TMP objects.");
    if (!description || !description.trim()) throw new Error("Refusing to create a transport with an empty description.");

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    // Verified against the open-source abap-adt-api client's createTransport()
    // (github.com/marcellourbani/abap-adt-api, src/api/transports.ts): POST
    // /sap/bc/adt/cts/transports with an asx:abap DATA envelope carrying
    // DEVCLASS/REQUEST_TEXT/REF/OPERATION, dataname CreateCorrectionRequest.
    // REF only has to be URL-SHAPED (ValidateObjectUrl there is a regex, not
    // an existence check) - the package's own ADT URI works, so no real
    // object needs to exist yet.
    const mediaType = "application/vnd.sap.as+xml; charset=UTF-8; dataname=com.sap.adt.CreateCorrectionRequest";
    const body =
      `<?xml version="1.0" encoding="UTF-8"?><asx:abap xmlns:asx="http://www.sap.com/abapxml" version="1.0">\n` +
      `  <asx:values>\n` +
      `    <DATA>\n` +
      `      <DEVCLASS>${escapeXml(dc)}</DEVCLASS>\n` +
      `      <REQUEST_TEXT>${escapeXml(description)}</REQUEST_TEXT>\n` +
      `      <REF>/sap/bc/adt/packages/${encodeURIComponent(devclass.toLowerCase())}</REF>\n` +
      `      <OPERATION>I</OPERATION>\n` +
      `    </DATA>\n` +
      `  </asx:values>\n` +
      `</asx:abap>`;

    const qs = transportLayer ? `?transportLayer=${encodeURIComponent(transportLayer)}` : "";
    const res = await fetch(`${profile().host}/sap/bc/adt/cts/transports${qs}`, {
      method: "POST",
      headers: { ...authHeaders("text/plain"), "X-CSRF-Token": token, "Content-Type": mediaType, Cookie: cookies },
      body,
      agent,
    });
    cookies = mergeCookies(cookies, res);
    const text = await res.text();
    if (!res.ok) throw new Error(`Create transport failed (${res.status}). ${text}`);

    // Success returns the new request's own ADT URI as a plain-text body
    // (e.g. "/sap/bc/adt/cts/transports/D01K900123") - the number is the
    // last path segment.
    const number = text.trim().split("/").filter(Boolean).pop();
    if (!number) throw new Error(`Transport created but couldn't parse its number from the response: ${text}`);

    return { content: [{ type: "text", text: `Created transport ${number} for package ${dc}: "${description}"` }] };
  }
);

server.tool(
  "release_transport",
  "Release a transport request (or task) - the write counterpart to get_transport_details. Runs SAP's " +
  "standard release checks and moves it from modifiable to released, so it can be imported into the next " +
  "system. Refuses to run on production/read-only profiles. Use get_transport_details first to see what's " +
  "actually registered under it before releasing.",
  {
    transport: z.string().describe("Transport request or task number, e.g. D01K900123"),
    ignoreLocks: z.boolean().optional().default(false)
      .describe("Release even if some objects are locked in other requests. Only set this when you understand why - it can leave inconsistent state."),
    ignoreAtcCheck: z.boolean().optional().default(false)
      .describe("Skip the ATC (code quality) check that normally runs on release. Only set this when you understand why."),
  },
  async ({ transport, ignoreLocks, ignoreAtcCheck }) => {
    assertWritable();
    const tr = transport.toUpperCase().trim();
    if (!tr) throw new Error("Transport number is required.");

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    // Verified against the open-source abap-adt-api client's transportRelease()
    // (github.com/marcellourbani/abap-adt-api, src/api/transports.ts): POST
    // /sap/bc/adt/cts/transportrequests/{tr}/{action}, no body - action picks
    // the release variant: newreleasejobs (normal), relwithignlock (skip lock
    // conflicts), relObjigchkatc (skip the ATC check).
    const action = ignoreAtcCheck ? "relObjigchkatc" : ignoreLocks ? "relwithignlock" : "newreleasejobs";
    const res = await fetch(
      `${profile().host}/sap/bc/adt/cts/transportrequests/${encodeURIComponent(tr)}/${action}`,
      { method: "POST", headers: { ...authHeaders("application/*"), "X-CSRF-Token": token, Cookie: cookies }, agent }
    );
    cookies = mergeCookies(cookies, res);
    const text = await res.text();
    if (!res.ok) throw new Error(`Release failed for ${tr} (${res.status}). ${text}`);

    // Response: <tm:root>...<tm:releasereports><chkrun:checkReport chkrun:reporter=".."
    // chkrun:status="released|abortrelapifail" chkrun:statusText="..">
    //   <chkrun:checkMessageList><chkrun:checkMessage chkrun:type=".." chkrun:shortText=".."/></...>
    // </chkrun:checkReport>...  Extracted flat (report attrs, message attrs)
    // rather than nested, since a self-closing <chkrun:checkReport/> with no
    // messages would otherwise swallow the next sibling's content.
    const attrsOf = (tagStr, ns) => {
      const out = {};
      for (const m of String(tagStr || "").matchAll(new RegExp(`${ns}:([\\w-]+)="([^"]*)"`, "g"))) out[m[1]] = decodeXml(m[2]);
      return out;
    };
    const reports = [...text.matchAll(/<chkrun:checkReport\b([^>]*?)\/?>/g)].map(m => attrsOf(m[1], "chkrun"));
    const messages = [...text.matchAll(/<chkrun:checkMessage\b([^>]*?)\/?>/g)].map(m => attrsOf(m[1], "chkrun"));

    if (!reports.length && !messages.length) {
      return { content: [{ type: "text", text: `Release request sent for ${tr}. No structured report came back - run get_transport_details to confirm its new status.` }] };
    }

    const log = [`Release result for ${tr}:`];
    for (const r of reports) {
      log.push(`  ${r.reporter || "?"}: ${r.status || "?"}${r.statusText ? ` - ${r.statusText}` : ""}`);
    }
    if (messages.length) {
      log.push(`\nMessages:`);
      for (const m of messages) log.push(`  [${m.type || "?"}] ${m.shortText || ""}${m.uri ? `  (${m.uri})` : ""}`);
    }
    const failed = reports.some(r => r.status && r.status !== "released");
    if (failed) {
      log.push(`\nNot fully released - see messages above. If appropriate, retry with ignoreLocks or ` +
        `ignoreAtcCheck once you understand why it failed.`);
    }
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "syntax_check",
  "Run the ABAP syntax/consistency check (the same check ADT runs) on an existing object WITHOUT activating " +
  "it. Read-only and safe on any profile, including production. Use this after writing source and BEFORE " +
  "activate_object - it reports errors and warnings so you can fix them first. To check source you have just " +
  "written but not yet activated, pass version=\"inactive\".",
  {
    objectUri: z.string().describe("ADT URI of the object, e.g. /sap/bc/adt/oo/classes/zcl_foo or /sap/bc/adt/ddic/ddl/sources/zi_foo (with or without /source/main)"),
    version: z.enum(["active", "inactive"]).optional().default("active")
      .describe("Which version to check. Use 'inactive' for source that is saved but not yet activated."),
  },
  async ({ objectUri, version }) => {
    const host = profile().host;
    // Normalise: the check runs against the object's source URI.
    const base = String(objectUri).replace(/\/source\/main\b.*$/, "").replace(/\/+$/, "");
    const sourceUri = `${base}/source/main`;

    const { token, cookies } = await fetchCsrfToken();
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const body =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<chkrun:checkObjectList xmlns:chkrun="http://www.sap.com/adt/checkrun" xmlns:adtcore="http://www.sap.com/adt/core">\n` +
      `  <chkrun:checkObject adtcore:uri="${escapeXml(sourceUri)}" chkrun:version="${version}"/>\n` +
      `</chkrun:checkObjectList>`;

    const res = await fetch(`${host}/sap/bc/adt/checkruns?reporters=abapCheckRun`, {
      method: "POST",
      headers: {
        ...authHeaders("application/vnd.sap.adt.checkmessages+xml"),
        "X-CSRF-Token": token,
        Cookie: cookies,
        "Content-Type": "application/vnd.sap.adt.checkobjects+xml",
      },
      body,
      agent,
    });
    const xml = await res.text();
    if (!res.ok) throw new Error(`Syntax check failed (${res.status}). ${xml}`);

    const status = (xml.match(/chkrun:status="([^"]*)"/) || [])[1] || "";
    const statusText = (xml.match(/chkrun:statusText="([^"]*)"/) || [])[1] || "";
    const log = [`Object: ${base}  (version: ${version})`];

    if (status === "notProcessed") {
      log.push(`NOT CHECKED: ${statusText || "object could not be checked"}`);
      return { content: [{ type: "text", text: log.join("\n") }] };
    }

    // Each finding is a chkrun:checkMessage with a type (E/W/I) and short text.
    const messages = [...xml.matchAll(/<chkrun:checkMessage\b([^>]*)\/?>/g)].map(m => {
      const attrs = m[1];
      const get = (a) => (attrs.match(new RegExp(`chkrun:${a}="([^"]*)"`)) || [])[1] || "";
      return { type: get("type"), text: get("shortText"), uri: get("uri") };
    });

    const errors = messages.filter(m => /^E/i.test(m.type));
    const warnings = messages.filter(m => /^W/i.test(m.type));
    const others = messages.filter(m => !/^[EW]/i.test(m.type));

    if (!messages.length) {
      log.push(`OK - no syntax errors. ${statusText}`);
    } else {
      log.push(`${errors.length} error(s), ${warnings.length} warning(s), ${others.length} other.`);
      for (const m of [...errors, ...warnings, ...others]) {
        log.push(`  [${m.type || "?"}] ${decodeXml(m.text)}${m.uri ? `  (${m.uri})` : ""}`);
      }
    }
    // If the report says something is wrong but no messages parsed, never hide it.
    if (!messages.length && status && status !== "processed") {
      log.push(`Unparsed report (status="${status}"). Raw response:\n${xml.slice(0, 1500)}`);
    }
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "where_used",
  "Find where an object is used (the ADT 'where-used list'). Read-only and safe on any profile. Use it before " +
  "changing or deleting something to see what depends on it. Results can be huge, so they are capped - the " +
  "total count is always reported.",
  {
    objectUri: z.string().describe("ADT URI of the object, e.g. /sap/bc/adt/ddic/tables/ztjplant_email or /sap/bc/adt/oo/classes/zcl_foo"),
    maxResults: z.number().optional().default(50).describe("How many references to list (default 50). The true total is always reported."),
  },
  async ({ objectUri, maxResults }) => {
    const host = profile().host;
    const uri = String(objectUri).replace(/\/source\/main\b.*$/, "").replace(/\/+$/, "");

    const { token, cookies } = await fetchCsrfToken();
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const body =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<usagereferences:usageReferenceRequest xmlns:usagereferences="http://www.sap.com/adt/ris/usageReferences">\n` +
      `  <usagereferences:affectedObjects/>\n` +
      `</usagereferences:usageReferenceRequest>`;

    const res = await fetch(
      `${host}/sap/bc/adt/repository/informationsystem/usageReferences?uri=${encodeURIComponent(uri)}`,
      {
        method: "POST",
        headers: {
          ...authHeaders("application/vnd.sap.adt.repository.usagereferences.result.v1+xml"),
          "X-CSRF-Token": token,
          Cookie: cookies,
          "Content-Type": "application/vnd.sap.adt.repository.usagereferences.request.v1+xml",
        },
        body,
        agent,
      }
    );
    const xml = await res.text();
    if (!res.ok) throw new Error(`Where-used failed (${res.status}). ${xml}`);

    const total = (xml.match(/numberOfResults="(\d+)"/) || [])[1] || "0";
    const what = decodeXml((xml.match(/resultDescription="([^"]*)"/) || [])[1] || uri);

    // Each hit carries an adtcore:name/type/description on the inner adtObject.
    const hits = [...xml.matchAll(/<adtcore:objectReference\b[^>]*\/>|<adtcore:adtObject\b[^>]*|<usageReferences:adtObject\b[^>]*/g)]
      .map(m => {
        const a = m[0];
        const g = (k) => (a.match(new RegExp(`adtcore:${k}="([^"]*)"`)) || [])[1] || "";
        return { name: g("name"), type: g("type"), desc: decodeXml(g("description")) };
      })
      // Drop the package refs that ride along with each hit - they are not usages.
      .filter(h => h.name && h.type !== "DEVC/K");

    const log = [`Where-used: ${what}`, `Total references: ${total}`];
    if (!hits.length) {
      log.push("No individual references could be parsed from the response.");
      if (Number(total) > 0) log.push(`Raw response (truncated):\n${xml.slice(0, 1200)}`);
    } else {
      const shown = hits.slice(0, Math.max(1, maxResults));
      log.push(`Showing ${shown.length} of ${hits.length} parsed:`);
      for (const h of shown) log.push(`  ${h.type.padEnd(9)} ${h.name}${h.desc ? ` - ${h.desc}` : ""}`);
      if (hits.length > shown.length) log.push(`  ... ${hits.length - shown.length} more (raise maxResults to see them)`);
    }
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "run_atc",
  "Run an ATC (ABAP Test Cockpit) static-analysis check on an object and report the findings. Read-only and " +
  "safe on any profile. Use it before releasing a transport, or after building something, to catch the issues " +
  "your team's ATC variant enforces. Slower than syntax_check - use syntax_check for quick error checking.",
  {
    objectUri: z.string().describe("ADT URI of the object, e.g. /sap/bc/adt/oo/classes/zcl_foo"),
    checkVariant: z.string().optional().describe("ATC check variant. Defaults to the system's configured variant."),
    maxFindings: z.number().optional().default(100).describe("Maximum findings to request (default 100)"),
  },
  async ({ objectUri, checkVariant, maxFindings }) => {
    const host = profile().host;
    const uri = String(objectUri).replace(/\/source\/main\b.*$/, "").replace(/\/+$/, "");

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method = "GET", headers = {}, body, accept = "*/*" } = {}) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, Cookie: cookies, ...headers },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    // 1) which check variant? ask the system if the caller didn't say.
    let variant = checkVariant;
    if (!variant) {
      const cust = await call("/sap/bc/adt/atc/customizing");
      variant = (cust.text.match(/name="systemCheckVariant"\s+value="([^"]*)"/) || [])[1] || "DEFAULT";
    }

    // 2) open a worklist for that variant
    const wl = await call(`/sap/bc/adt/atc/worklists?checkVariant=${encodeURIComponent(variant)}`,
      { method: "POST", accept: "text/plain" });
    if (!wl.ok) throw new Error(`Could not create an ATC worklist (${wl.status}). ${wl.text}`);
    const worklistId = wl.text.trim();

    // 3) run the check over this one object
    const runBody =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<atc:run xmlns:atc="http://www.sap.com/adt/atc" maximumVerdicts="${Math.max(1, maxFindings)}">\n` +
      `  <objectSets xmlns:adtcore="http://www.sap.com/adt/core">\n` +
      `    <objectSet kind="inclusive">\n` +
      `      <adtcore:objectReferences>\n` +
      `        <adtcore:objectReference adtcore:uri="${escapeXml(uri)}"/>\n` +
      `      </adtcore:objectReferences>\n` +
      `    </objectSet>\n` +
      `  </objectSets>\n` +
      `</atc:run>`;
    const run = await call(`/sap/bc/adt/atc/runs?worklistId=${encodeURIComponent(worklistId)}`,
      { method: "POST", headers: { "Content-Type": "application/xml" }, body: runBody });
    if (!run.ok) throw new Error(`ATC run failed (${run.status}). ${run.text}`);
    const stats = (run.text.match(/<atcinfo:description>([^<]*)<\/atcinfo:description>/) || [])[1] || "";

    // 4) read the findings back off the worklist
    const res = await call(`/sap/bc/adt/atc/worklists/${encodeURIComponent(worklistId)}?includeExemptedFindings=false`,
      { accept: "application/atc.worklist.v1+xml" });
    if (!res.ok) throw new Error(`Could not read the ATC worklist (${res.status}). ${res.text}`);

    const findings = [...res.text.matchAll(/<atcfinding:finding\b([^>]*)/g)].map(m => {
      const a = m[1];
      const g = (k) => (a.match(new RegExp(`(?:atcfinding:)?${k}="([^"]*)"`)) || [])[1] || "";
      return {
        priority: g("priority"),
        check: decodeXml(g("checkTitle")),
        message: decodeXml(g("messageTitle")),
        uri: g("location") || g("uri"),
      };
    });

    const log = [`ATC check of ${uri}`, `Variant: ${variant}`];
    if (stats) log.push(`Finding stats (prio 1,2,3): ${stats}`);
    if (!findings.length) {
      log.push(/^[0,\s]*$/.test(stats) ? "OK - no ATC findings." : "No individual findings parsed.");
      if (stats && !/^[0,\s]*$/.test(stats)) log.push(`Raw worklist (truncated):\n${res.text.slice(0, 1200)}`);
    } else {
      log.push(`${findings.length} finding(s):`);
      for (const f of findings.slice(0, Math.max(1, maxFindings))) {
        log.push(`  [prio ${f.priority || "?"}] ${f.message || f.check}${f.check && f.message ? `  (${f.check})` : ""}`);
      }
    }
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "activate_object",
  "Activate one or more existing ABAP objects and report the raw activation result. " +
  "Pass a single object (objectUri + objectName), or several at once via `objects` - " +
  "activating together is required for mutually-dependent RAP objects, e.g. a behavior " +
  "definition and its behavior implementation class. Blocked on production profiles.",
  {
    objectUri: z.string().optional().describe("ADT URI of a single object, e.g. /sap/bc/adt/oo/classes/zcl_foo"),
    objectName: z.string().optional().describe("Name of the single object, e.g. ZCL_FOO"),
    objects: z.array(z.object({
      objectUri: z.string().describe("ADT URI"),
      objectName: z.string().describe("Object name"),
    })).optional().describe("Activate several objects together (needed for a BDEF + its behavior class)."),
  },
  async ({ objectUri, objectName, objects }) => {
    assertWritable();

    const refs = [];
    if (objectUri && objectName) refs.push({ uri: objectUri, name: objectName.toUpperCase() });
    for (const o of objects || []) refs.push({ uri: o.objectUri, name: o.objectName.toUpperCase() });
    if (!refs.length) throw new Error("Provide objectUri+objectName, or a non-empty objects array.");

    const { token, cookies: initial } = await fetchCsrfToken();
    const body =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">\n` +
      refs.map(r => `  <adtcore:objectReference adtcore:uri="${r.uri}" adtcore:name="${escapeXml(r.name)}"/>`).join("\n") +
      `\n</adtcore:objectReferences>`;

    const res = await fetch(
      `${profile().host}/sap/bc/adt/activation?method=activate&preauditRequests=false`,
      {
        method: "POST",
        headers: {
          ...authHeaders("application/xml"),
          "Content-Type": "application/xml",
          "X-CSRF-Token": token,
          Cookie: initial,
        },
        body,
        agent,
      }
    );
    const text = await res.text();
    const msgs = parseActivationMessages(text);

    const out = [`HTTP ${res.status} (${refs.map(r => r.name).join(", ")})`];
    if (msgs.length) for (const m of msgs) out.push(`  [${m.type}] ${m.text}`);
    else out.push(`  Body: ${text ? text.slice(0, 2000) : "(empty - usually means success)"}`);
    return { content: [{ type: "text", text: out.join("\n") }] };
  }
);

server.tool(
  "update_program_source",
  "Overwrite the source of an EXISTING ABAP program or include (report, include, module pool). " +
  "Resolves program-vs-include automatically, then locks, PUTs the source, optionally activates, and unlocks. " +
  "Refuses to run on production profiles. IMPORTANT: this replaces the WHOLE object - always read it first " +
  "with get_program_source, edit that text, and send the complete result back.",
  {
    programName: z.string().describe("Program or include name, e.g. ZABLMMNF00002TOP"),
    source: z.string().describe("Complete new ABAP source - REPLACES the entire object"),
    transport: z.string().optional().describe("Transport request, e.g. D01K900123. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE38/SE80 yourself."),
  },
  async ({ programName, source, transport: corrNr, activate }) => {
    assertWritable();

    if (!source || !source.trim()) {
      throw new Error("Refusing to write an empty source - that would wipe the object.");
    }

    const name = programName.toUpperCase();
    const lower = programName.toLowerCase();
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    };

    // Reports live under programs/programs, includes under programs/includes.
    let uri = null;
    let before = "";
    for (const candidate of [
      `/sap/bc/adt/programs/programs/${lower}`,
      `/sap/bc/adt/programs/includes/${lower}`,
    ]) {
      const probe = await call(`${candidate}/source/main`, { method: "GET", accept: "text/plain" });
      if (probe.ok) { uri = candidate; before = probe.text; break; }
      if (probe.status !== 404) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);
    }
    if (!uri) throw new Error(`Program/include ${name} not found (tried programs/ and includes/).`);
    log.push(`Target: ${uri}`);
    log.push(`Current size: ${before.split("\n").length} lines -> new: ${source.split("\n").length} lines.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);

      if (activate) {
        const actBody =
          `<?xml version="1.0" encoding="UTF-8"?>\n` +
          `<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">\n` +
          `  <adtcore:objectReference adtcore:uri="${uri}" adtcore:name="${escapeXml(name)}"/>\n` +
          `</adtcore:objectReferences>`;
        const act = await call(`/sap/bc/adt/activation?method=activate&preauditRequests=false`, {
          method: "POST",
          headers: { "Content-Type": "application/xml" },
          body: actBody,
        });
        const msgs = parseActivationMessages(act.text);
        const bad = msgs.filter(m => /^[EAW]$/i.test(m.type));
        if (!act.ok || bad.length) {
          log.push(`ACTIVATION FAILED (HTTP ${act.status}) - source IS saved but the object is INACTIVE.`);
          for (const m of (bad.length ? bad : msgs)) log.push(`  [${m.type}] ${m.text}`);
          if (!bad.length) log.push(`  Raw response: ${(act.text || "(empty body)").slice(0, 1500)}`);
        } else {
          log.push("Activated cleanly.");
        }
      } else {
        log.push("Not activated (activate=false) - activate it in SE38/SE80.");
      }
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "patch_program_source",
  "Modify PART of an existing ABAP program or include without resending the whole object. " +
  "Reads the current source, replaces oldString with newString (must match EXACTLY ONCE), then locks, PUTs, " +
  "optionally activates, and unlocks. Prefer this over update_program_source for edits - it removes any risk of " +
  "corrupting the object by re-transmitting untouched code. Refuses to run on production profiles.",
  {
    programName: z.string().describe("Program or include name, e.g. ZABLMMNF00002TOP"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request, e.g. D01K903926. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE38/SE80 yourself."),
  },
  async ({ programName, oldString, newString, transport: corrNr, activate }) => {
    assertWritable();

    if (!oldString) throw new Error("oldString must not be empty.");
    if (oldString === newString) throw new Error("oldString and newString are identical - nothing to do.");

    const name = programName.toUpperCase();
    const lower = programName.toLowerCase();
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    };

    // Reports live under programs/programs, includes under programs/includes.
    let uri = null;
    let before = null;
    for (const candidate of [
      `/sap/bc/adt/programs/programs/${lower}`,
      `/sap/bc/adt/programs/includes/${lower}`,
    ]) {
      const probe = await call(`${candidate}/source/main`, { method: "GET", accept: "text/plain" });
      if (probe.ok) { uri = candidate; before = probe.text; break; }
      if (probe.status !== 404) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);
    }
    if (uri === null) throw new Error(`Program/include ${name} not found (tried programs/ and includes/).`);

    // ADT hands source back with CRLF; callers naturally write LF. Normalise both
    // sides so a multi-line oldString can match. ABAP source is stored server-side
    // as a line table, so the line endings we PUT are not persisted verbatim.
    const nl = s => String(s).replace(/\r\n/g, "\n");
    before = nl(before);
    oldString = nl(oldString);
    newString = nl(newString);

    // Exact-match replace, server side: nothing outside oldString can be disturbed.
    const hits = before.split(oldString).length - 1;
    if (hits === 0) {
      // Help the caller find the drift instead of making them guess.
      const firstLine = oldString.split("\n")[0];
      const near = before.split("\n").filter(l => l.includes(firstLine.trim()) && firstLine.trim());
      throw new Error(
        `oldString not found in ${name}. Nothing written.` +
        (near.length ? ` Lines containing the first line of oldString: ${JSON.stringify(near.slice(0, 5))}` : "")
      );
    }
    if (hits > 1) throw new Error(`oldString matched ${hits} times in ${name}. Nothing written. Add surrounding context to make it unique.`);
    const after = before.replace(oldString, newString);

    log.push(`Target: ${uri}`);
    log.push(`Patched 1 occurrence. Lines ${before.split("\n").length} -> ${after.split("\n").length}.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: after }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);

      if (activate) {
        const actBody =
          `<?xml version="1.0" encoding="UTF-8"?>\n` +
          `<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">\n` +
          `  <adtcore:objectReference adtcore:uri="${uri}" adtcore:name="${escapeXml(name)}"/>\n` +
          `</adtcore:objectReferences>`;
        const act = await call(`/sap/bc/adt/activation?method=activate&preauditRequests=false`, {
          method: "POST",
          headers: { "Content-Type": "application/xml" },
          body: actBody,
        });
        const msgs = parseActivationMessages(act.text);
        const bad = msgs.filter(m => /^[EAW]$/i.test(m.type));
        if (!act.ok || bad.length) {
          log.push(`ACTIVATION FAILED (HTTP ${act.status}) - source IS saved but the object is INACTIVE.`);
          for (const m of (bad.length ? bad : msgs)) log.push(`  [${m.type}] ${m.text}`);
          if (!bad.length) log.push(`  Raw response: ${(act.text || "(empty body)").slice(0, 1500)}`);
        } else {
          log.push("Activated cleanly.");
        }
      } else {
        log.push("Not activated (activate=false) - activate it in SE38/SE80.");
      }
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

// Text elements (text symbols/selection texts/list headings) are a SEPARATE
// ADT sub-resource from a program/class/function group's source - they don't
// live in the source itself, so update_program_source etc. can never touch
// them. Verified against the open-source abap-adt-api client and its own
// test suite (github.com/marcellourbani/abap-adt-api, src/api/textelements.ts):
// URL is /sap/bc/adt/textelements/{programs|classes|functiongroups}/<name>,
// read/write is GET/PUT .../source/<category> with an
// application/vnd.sap.adt.textelements.<category>.v1 media type, and the lock
// target is that textelements URL itself (not the object's main source URI).
// Unlike source code, text elements need NO activation step - confirmed by
// that client's own disruptive write test (lock -> get -> PUT -> done).
function textElementsUri(objectType, name) {
  const lower = name.toLowerCase();
  const encoded = lower.includes("/") ? encodeURIComponent(lower) : lower;
  const t = String(objectType || "").toUpperCase();
  if (t.startsWith("CLAS")) return `/sap/bc/adt/textelements/classes/${encoded}`;
  if (t.startsWith("FUGR")) return `/sap/bc/adt/textelements/functiongroups/${encoded}`;
  return `/sap/bc/adt/textelements/programs/${encoded}`;
}

// Body format is line-based key=text pairs, blank-line separated, with an
// optional @MaxLength:n line (symbols only) immediately before an entry.
function parseTextElements(body) {
  const elements = [];
  let pendingMaxLength;
  for (const raw of String(body || "").split("\n")) {
    // Only used to detect blank separator lines and the @MaxLength marker -
    // the text itself is sliced from the UNTRIMMED line below, so meaningful
    // trailing spaces in an existing symbol's value (common in aligned report
    // headers) survive a read-merge-write round trip instead of being
    // silently stripped every time an unrelated symbol on the same object
    // gets patched.
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const m = /^@MaxLength:(\d+)$/.exec(trimmed);
    if (m) { pendingMaxLength = parseInt(m[1], 10); continue; }
    const eq = raw.indexOf("=");
    if (eq <= 0) continue;
    const id = raw.slice(0, eq).trim();
    const text = raw.slice(eq + 1).replace(/\r$/, "");
    elements.push(pendingMaxLength ? { id, text, maxLength: pendingMaxLength } : { id, text });
    pendingMaxLength = undefined;
  }
  return elements;
}

function formatTextElements(elements) {
  const lines = [];
  for (const el of elements) {
    if (el.maxLength) lines.push(`@MaxLength:${el.maxLength}`);
    lines.push(`${el.id.toUpperCase()}=${el.text}`);
    lines.push("");
  }
  return lines.join("\n");
}

server.tool(
  "get_text_elements",
  "Read the raw TEXT SYMBOLS (TEXT-xxx) text-pool content for an existing ABAP program, class, or " +
  "function group - the read-only counterpart to patch_text_elements (which can only write, not read). " +
  "Returns the exact raw content ADT returns (line-based id=text pairs, with an @MaxLength:n marker " +
  "where set) - useful for seeing precisely what's stored when debugging a mismatch, rather than " +
  "guessing from patch_text_elements' own merge log. Read-only, safe on any profile including " +
  "production.",
  {
    objectName: z.string().describe("Program, class, or function group name, e.g. ZRM_STOCK_MOVEMENT_HK"),
    objectType: z.enum(["PROG", "CLAS", "FUGR"]).optional().default("PROG").describe("Object kind. Default PROG (report/include)."),
  },
  async ({ objectName, objectType }) => {
    const name = objectName.toUpperCase();
    const uri = textElementsUri(objectType, name);
    const mediaType = "application/vnd.sap.adt.textelements.symbols.v1";
    let text;
    try {
      text = await adtGet(`${uri}/source/symbols`, mediaType);
    } catch (err) {
      // A 404 here just means this object has no text symbols yet - same
      // "not an error" treatment patch_text_elements already gives it.
      if (/SAP ADT error 404/.test(String(err && err.message))) {
        return { content: [{ type: "text", text: `${name} has no text symbols (or does not exist).` }] };
      }
      throw err;
    }
    return { content: [{ type: "text", text: text && text.trim() ? text : `${name} has no text symbols.` }] };
  }
);

server.tool(
  "patch_text_elements",
  "Add or update TEXT SYMBOLS (TEXT-xxx) for an existing ABAP program, class, or function group. " +
  "This is a SEPARATE ADT object from the source code - update_program_source/update_class etc. cannot touch it. " +
  "Reads the current text symbols, merges in the given ones (matched by 3-character id, case-insensitive; an " +
  "existing id is overwritten, a new one is added), then writes the merged result back. Existing symbols not " +
  "mentioned are left untouched. No activation needed - text elements take effect immediately once saved. " +
  "Refuses to run on production profiles.",
  {
    objectName: z.string().describe("Program, class, or function group name, e.g. ZRM_STOCK_MOVEMENT_HK"),
    objectType: z.enum(["PROG", "CLAS", "FUGR"]).optional().default("PROG").describe("Object kind. Default PROG (report/include)."),
    symbols: z.array(z.object({
      id: z.string().describe("3-character text symbol key, e.g. 001 or T01"),
      text: z.string().describe("The symbol's text"),
      maxLength: z.number().optional().describe("Optional max output length"),
    })).min(1).describe("Text symbols to add or update"),
    transport: z.string().optional().describe("Transport request, e.g. D01K900123. Omit only for local/$TMP objects."),
  },
  async ({ objectName, objectType, symbols, transport: corrNr }) => {
    assertWritable();

    const name = objectName.toUpperCase();
    const uri = textElementsUri(objectType, name);
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const mediaType = "application/vnd.sap.adt.textelements.symbols.v1";

    // 1) read current symbols (404 just means none exist yet - not an error)
    const probe = await call(`${uri}/source/symbols`, { method: "GET", accept: mediaType });
    if (!probe.ok && probe.status !== 404) throw new Error(`Cannot read text symbols for ${name} (${probe.status}). ${probe.text}`);
    const before = probe.ok ? parseTextElements(probe.text) : [];

    // 2) merge - overwrite by id (case-insensitive), append anything new
    const byId = new Map(before.map(el => [el.id.toUpperCase(), el]));
    for (const s of symbols) {
      const id = s.id.toUpperCase();
      if (id.length !== 3) throw new Error(`Symbol key "${s.id}" must be exactly 3 characters.`);
      byId.set(id, { id, text: s.text, maxLength: s.maxLength });
    }
    const merged = [...byId.values()];
    log.push(`${before.length} existing symbol(s), ${symbols.length} upserted -> ${merged.length} total.`);

    // 3) lock the TEXT ELEMENTS resource itself (not the object's source URI)
    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/symbols?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": `${mediaType}; charset=UTF-8`, Accept: mediaType }, body: formatTextElements(merged) }
      );
      if (!put.ok) throw new Error(`Text symbols PUT failed (${put.status}). ${put.text}`);
      log.push(`Text symbols written${corrNr ? ` on ${corrNr}` : ""}. No activation needed.`);
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "update_table",
  "Overwrite the source (field definitions) of an EXISTING DDIC database table. Locks, PUTs the whole new DDL " +
  "source, unlocks, then optionally activates. Refuses to run on production profiles. IMPORTANT: this REPLACES " +
  "the whole table definition - read it first, edit that text, and send the complete result back. Activating a " +
  "structure change triggers a DATABASE CONVERSION when the table holds data, so activate defaults to false; " +
  "review and activate in SE11. Prefer patch_table for small edits.",
  {
    tableName: z.string().describe("Table name, e.g. ZKIT_PRODUCT"),
    source: z.string().describe("Complete new DDL source - REPLACES the entire table definition"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP tables."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - a structure change may convert the DB; activate in SE11 yourself."),
  },
  async ({ tableName, source, transport: corrNr, activate }) => {
    assertWritable();
    if (!source || !source.trim()) throw new Error("Refusing to write an empty source - that would wipe the table.");

    const name = tableName.toUpperCase();
    const uri = `/sap/bc/adt/ddic/tables/${tableName.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    // Confirm the table exists (create_table, not this, makes new ones).
    const probe = await call(`${uri}/source/main`, { method: "GET", accept: "text/plain" });
    if (probe.status === 404) throw new Error(`Table ${name} not found. Use create_table to create a new one.`);
    if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);
    log.push(`Target: ${uri}`);
    log.push(`Current size: ${probe.text.split("\n").length} lines -> new: ${source.split("\n").length} lines.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, { method: "POST" });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    // Activate only after the lock is released.
    if (wrote && activate) await runActivation(call, uri, name, log, "table");
    else if (wrote) log.push("Not activated (activate=false) - review and activate in SE11 (a structure change may convert the DB).");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "patch_table",
  "Modify PART of an existing DDIC database table's DDL without resending the whole definition. Reads the " +
  "current source, replaces oldString with newString (must match EXACTLY ONCE), then locks, PUTs, unlocks, and " +
  "optionally activates. Prefer this over update_table for small edits like adding a field. Refuses to run on " +
  "production profiles. Activating a structure change may convert the DB, so activate defaults to false.",
  {
    tableName: z.string().describe("Table name, e.g. ZKIT_PRODUCT"),
    oldString: z.string().describe("Exact existing DDL text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP tables."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE11 yourself."),
  },
  async ({ tableName, oldString, newString, transport: corrNr, activate }) => {
    assertWritable();
    if (!oldString) throw new Error("oldString must not be empty.");
    if (oldString === newString) throw new Error("oldString and newString are identical - nothing to do.");

    const name = tableName.toUpperCase();
    const uri = `/sap/bc/adt/ddic/tables/${tableName.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const probe = await call(`${uri}/source/main`, { method: "GET", accept: "text/plain" });
    if (probe.status === 404) throw new Error(`Table ${name} not found. Use create_table to create a new one.`);
    if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);

    const nl = s => String(s).replace(/\r\n/g, "\n");
    const before = nl(probe.text);
    oldString = nl(oldString);
    newString = nl(newString);

    const hits = before.split(oldString).length - 1;
    if (hits === 0) {
      const firstLine = oldString.split("\n")[0];
      const near = before.split("\n").filter(l => l.includes(firstLine.trim()) && firstLine.trim());
      throw new Error(`oldString not found in ${name}. Nothing written.` + (near.length ? ` Lines containing the first line of oldString: ${JSON.stringify(near.slice(0, 5))}` : ""));
    }
    if (hits > 1) throw new Error(`oldString matched ${hits} times in ${name}. Nothing written. Add surrounding context to make it unique.`);
    const after = before.replace(oldString, newString);

    log.push(`Target: ${uri}`);
    log.push(`Patched 1 occurrence. Lines ${before.split("\n").length} -> ${after.split("\n").length}.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: after }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, { method: "POST" });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    if (wrote && activate) await runActivation(call, uri, name, log, "table");
    else if (wrote) log.push("Not activated (activate=false) - review and activate in SE11.");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "create_function_group",
  "Create a new function group (the container that holds function modules). Refuses to run on production " +
  "profiles. Add modules afterwards with create_function_module. Needs a transport unless package is $TMP.",
  {
    functionGroup: z.string().describe("Function group name WITHOUT the SAPL prefix, e.g. ZABL_UTIL"),
    description: z.string().describe("Short description"),
    packageName: z.string().describe("Package, e.g. ZABAP. Use $TMP for a local throwaway."),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP."),
  },
  async ({ functionGroup, description, packageName, transport: corrNr }) => {
    assertWritable();
    const name = functionGroup.toUpperCase();
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<group:abapFunctionGroup xmlns:group="http://www.sap.com/adt/functions/groups" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="FUGR/F" adtcore:masterLanguage="EN" adtcore:language="EN">\n` +
      `  <adtcore:packageRef adtcore:name="${escapeXml(packageName.toUpperCase())}"/>\n` +
      `</group:abapFunctionGroup>`;

    const created = await call(`/sap/bc/adt/functions/groups${corrQuery}`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.sap.adt.functions.groups.v3+xml" },
      body: shell,
    });
    if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
    log.push(`Created function group ${name} in package ${packageName.toUpperCase()}${corrNr ? ` on ${corrNr}` : ""}.`);
    log.push("Add function modules with create_function_module.");
    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "create_function_module",
  "Create a new function module inside an EXISTING function group, write its source, and optionally activate. " +
  "Refuses to run on production profiles. Create the group first with create_function_group. Provide the full " +
  "source/main text (FUNCTION <name>. ... ENDFUNCTION.).",
  {
    functionGroup: z.string().describe("Function group name WITHOUT the SAPL prefix, e.g. ZABL_UTIL"),
    functionModule: z.string().describe("Function module name, e.g. Z_ABL_DO_THING"),
    description: z.string().describe("Short description"),
    source: z.string().describe("Complete FM source as ADT stores it (FUNCTION ... ENDFUNCTION.)"),
    transport: z.string().optional().describe("Transport request. Omit only for $TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE37/SE80."),
  },
  async ({ functionGroup, functionModule, description, source, transport: corrNr, activate }) => {
    assertWritable();
    if (!source || !source.trim()) throw new Error("Refusing to create a function module with empty source.");

    const grp = functionGroup.toLowerCase();
    const fm = functionModule.toLowerCase();
    const name = functionModule.toUpperCase();
    const uri = `/sap/bc/adt/functions/groups/${grp}/fmodules/${fm}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const corrQuery = corrNr ? `?corrNr=${encodeURIComponent(corrNr)}` : "";
    const shell =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<fmodule:abapFunctionModule xmlns:fmodule="http://www.sap.com/adt/functions/fmodules" ` +
      `xmlns:adtcore="http://www.sap.com/adt/core" ` +
      `adtcore:description="${escapeXml(description)}" adtcore:name="${escapeXml(name)}" ` +
      `adtcore:type="FUGR/FF" adtcore:masterLanguage="EN">\n` +
      `  <adtcore:containerRef adtcore:name="${escapeXml(functionGroup.toUpperCase())}" adtcore:type="FUGR/F" ` +
      `adtcore:uri="/sap/bc/adt/functions/groups/${grp}"/>\n` +
      `</fmodule:abapFunctionModule>`;

    const created = await call(`/sap/bc/adt/functions/groups/${grp}/fmodules${corrQuery}`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.sap.adt.functions.fmodules.v3+xml" },
      body: shell,
    });
    if (!created.ok) throw new Error(`Create failed (${created.status}). ${created.text}`);
    log.push(`Created function module ${name} in group ${functionGroup.toUpperCase()}.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, { method: "POST" });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    if (wrote && activate) await runActivation(call, uri, name, log, "function module");
    else if (wrote) log.push("Not activated (activate=false) - activate in SE37/SE80.");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "update_cds",
  "Overwrite the source of an EXISTING CDS view (DDLS). Locks, PUTs the whole new DDL source, unlocks, then " +
  "optionally activates. Refuses to run on production profiles. IMPORTANT: this REPLACES the whole CDS source - " +
  "read it first, edit that text, and send the complete result back. Keep the entity name unchanged. Prefer " +
  "patch_cds for small edits.",
  {
    cdsName: z.string().describe("CDS entity/DDLS name, e.g. ZKIT_I_PRODUCT"),
    source: z.string().describe("Complete new CDS DDL source - REPLACES the entire definition"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - CDS activation is safe (no DB conversion); pass true to activate in one call."),
  },
  async ({ cdsName, source, transport: corrNr, activate }) => {
    assertWritable();
    if (!source || !source.trim()) throw new Error("Refusing to write an empty source - that would wipe the CDS view.");

    const name = cdsName.toUpperCase();
    const uri = `/sap/bc/adt/ddic/ddl/sources/${cdsName.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const probe = await call(`${uri}/source/main`, { method: "GET", accept: "text/plain" });
    if (probe.status === 404) throw new Error(`CDS view ${name} not found. Use create_cds to create a new one.`);
    if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);
    log.push(`Target: ${uri}`);
    log.push(`Current size: ${probe.text.split("\n").length} lines -> new: ${source.split("\n").length} lines.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, { method: "POST" });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    if (wrote && activate) await runActivation(call, uri, name, log, "CDS view");
    else if (wrote) log.push("Not activated (activate=false) - activate in the CDS editor or with activate_object.");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "patch_cds",
  "Modify PART of an existing CDS view's DDL without resending the whole source. Reads the current source, " +
  "replaces oldString with newString (must match EXACTLY ONCE), then locks, PUTs, unlocks, and optionally " +
  "activates. Prefer this over update_cds for small edits like adding a field or annotation. Refuses to run on " +
  "production profiles.",
  {
    cdsName: z.string().describe("CDS entity/DDLS name, e.g. ZKIT_I_PRODUCT"),
    oldString: z.string().describe("Exact existing DDL text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - CDS activation is safe; pass true to activate in one call."),
  },
  async ({ cdsName, oldString, newString, transport: corrNr, activate }) => {
    assertWritable();
    if (!oldString) throw new Error("oldString must not be empty.");
    if (oldString === newString) throw new Error("oldString and newString are identical - nothing to do.");

    const name = cdsName.toUpperCase();
    const uri = `/sap/bc/adt/ddic/ddl/sources/${cdsName.toLowerCase()}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: { ...authHeaders(accept), "X-CSRF-Token": token, "x-sap-adt-sessiontype": "stateful", Cookie: cookies, ...headers },
        body, agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    const probe = await call(`${uri}/source/main`, { method: "GET", accept: "text/plain" });
    if (probe.status === 404) throw new Error(`CDS view ${name} not found. Use create_cds to create a new one.`);
    if (!probe.ok) throw new Error(`Cannot read ${name} (${probe.status}). ${probe.text}`);

    const nl = s => String(s).replace(/\r\n/g, "\n");
    const before = nl(probe.text);
    oldString = nl(oldString);
    newString = nl(newString);

    const hits = before.split(oldString).length - 1;
    if (hits === 0) {
      const firstLine = oldString.split("\n")[0];
      const near = before.split("\n").filter(l => l.includes(firstLine.trim()) && firstLine.trim());
      throw new Error(`oldString not found in ${name}. Nothing written.` + (near.length ? ` Lines containing the first line of oldString: ${JSON.stringify(near.slice(0, 5))}` : ""));
    }
    if (hits > 1) throw new Error(`oldString matched ${hits} times in ${name}. Nothing written. Add surrounding context to make it unique.`);
    const after = before.replace(oldString, newString);

    log.push(`Target: ${uri}`);
    log.push(`Patched 1 occurrence. Lines ${before.split("\n").length} -> ${after.split("\n").length}.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: after }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, { method: "POST" });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    if (wrote && activate) await runActivation(call, uri, name, log, "CDS view");
    else if (wrote) log.push("Not activated (activate=false) - activate in the CDS editor or with activate_object.");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

// --- source editors for class / BDEF / SRVD / function module --------------
// All share editSourceObject: read -> transform -> lock -> PUT -> unlock -> activate.

const classUri = n => `/sap/bc/adt/oo/classes/${n.toLowerCase()}`;
const bdefUri = n => `/sap/bc/adt/bo/behaviordefinitions/${n.toLowerCase()}`;
const srvdUri = n => `/sap/bc/adt/ddic/srvd/sources/${n.toLowerCase()}`;

// A class's local types (CCIMP include, "Local Types" tab in ADT/Eclipse),
// macros, and test classes are SEPARATE ADT sub-resources from its main
// source (/source/main, which only holds DEFINITION/IMPLEMENTATION) -
// update_class/patch_class can never reach them. Confirmed against the
// open-source abap-adt-api client (github.com/marcellourbani/abap-adt-api,
// src/api/objectstructure.ts): a class's object-structure response lists
// each include as a <class:include> element carrying its OWN <atom:link>
// source href - that client itself never hardcodes a URL for these, it
// always discovers the href from this response. These two tools do the same.
function parseClassIncludes(xml) {
  const includes = [];
  for (const m of xml.matchAll(/<class:include\b([^>]*)>([\s\S]*?)<\/class:include>/g)) {
    const attr = (n) => (m[1].match(new RegExp(`${n}="([^"]*)"`)) || [])[1] || "";
    const links = [...m[2].matchAll(/<atom:link\b([^>]*)\/?>/g)].map((lm) => {
      const la = (n) => (lm[1].match(new RegExp(`${n}="([^"]*)"`)) || [])[1] || "";
      return { href: la("href"), rel: la("rel") };
    });
    includes.push({ includeType: attr("class:includeType"), name: attr("adtcore:name"), links });
  }
  return includes;
}

// Pick the include's own source link - never a guessed/fixed URL pattern
// (see above). Prefers a link that looks like a source endpoint; ambiguous
// otherwise so a wrong guess can never silently read/write the wrong thing.
//
// This system's ADT reports these hrefs as BARE RELATIVE paths (e.g.
// "includes/definitions", no leading slash - confirmed live against
// ZMMCL_BP_GOODS_MVT on DS4100) rather than absolute ones, so they must be
// resolved against the class's own base URI, not just normalized. Every
// caller here builds requests as `${host}${path}`, so the result is always
// handed back as a path (never scheme+host).
function classIncludeSourceUri(include, host, baseUri) {
  const bySuffix = include.links.find((l) => /\/source\/main$/i.test(l.href));
  const byRel = bySuffix || include.links.find((l) => /source/i.test(l.rel || ""));
  const link = byRel || (include.links.length === 1 ? include.links[0] : null);
  if (!link) return null;
  try {
    // The trailing "/" on the base is essential: without it, WHATWG URL
    // resolution treats the class name as a "file" and replaces it instead
    // of appending the relative segment underneath it.
    const resolved = new URL(link.href, `${host}${baseUri}/`);
    return resolved.pathname + resolved.search;
  } catch {
    return null;
  }
}

server.tool(
  "list_class_includes",
  "List a class's separate ADT includes - e.g. local types (the CCIMP include / 'Local " +
  "Types' tab in ADT), macros, test classes - each a DIFFERENT source object from the " +
  "class's own main source (/source/main = DEFINITION/IMPLEMENTATION only). Run this " +
  "BEFORE patch_class_include: it reports the exact includeType string THIS system uses " +
  "(never guessed) so you can target the right one. Read-only, safe on any profile " +
  "including production.",
  {
    className: z.string().describe("Class name, e.g. ZCL_ABL_PLANT_EMAIL"),
  },
  async ({ className }) => {
    const name = className.toUpperCase();
    const host = profile().host;
    const xml = await adtGet(classUri(className), "*/*");
    const includes = parseClassIncludes(xml);
    if (!includes.length) {
      return { content: [{ type: "text", text: `${name} reports no separate includes - only its main source exists.` }] };
    }
    const lines = includes.map((inc) => {
      const src = classIncludeSourceUri(inc, host, classUri(className));
      const raw = inc.links.map((l) => `${l.rel || "(no rel)"} -> ${l.href}`).join("; ");
      return `${inc.includeType || "(no includeType)"} (${inc.name || name}): ` +
        (src ? `source = ${src}` : `AMBIGUOUS - raw links: ${raw}`);
    });
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "patch_class_include",
  "Modify PART of a class's SEPARATE include - local types (CCIMP / 'Local Types' tab), " +
  "macros, or test classes - none of which live in /source/main (patch_class/update_class " +
  "cannot reach these). Run list_class_includes FIRST to get the exact includeType string. " +
  "Reads the include's current source, replaces oldString with newString (must match " +
  "EXACTLY ONCE), locks the class, PUTs to the discovered include source, unlocks, and " +
  "optionally activates the class. Refuses to run on production profiles.",
  {
    className: z.string().describe("Class name, e.g. ZCL_ABL_PLANT_EMAIL"),
    includeType: z.string().describe("Exact includeType reported by list_class_includes for the include you want to edit"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate the class after writing. Default false."),
  },
  async ({ className, includeType, oldString, newString, transport: corrNr, activate }) => {
    assertWritable();
    const name = className.toUpperCase();
    const uri = classUri(className);
    const host = profile().host;
    const log = [];

    const structXml = await adtGet(uri, "*/*");
    const includes = parseClassIncludes(structXml);
    const include = includes.find((i) => i.includeType.toLowerCase() === includeType.toLowerCase());
    if (!include) {
      const available = includes.map((i) => i.includeType || "(blank)").join(", ") || "(none found)";
      throw new Error(`No include of type "${includeType}" on ${name}. Available: ${available}. Run list_class_includes to check.`);
    }
    const sourceUri = classIncludeSourceUri(include, host, uri);
    if (!sourceUri) {
      throw new Error(
        `Found the "${includeType}" include on ${name} but its source link is ambiguous. ` +
        `Run list_class_includes to see its raw links and report this.`
      );
    }

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    // 1) read the include's current source (this tool edits; it never creates)
    const probe = await call(sourceUri, { method: "GET", accept: "text/plain" });
    if (!probe.ok) throw new Error(`Cannot read ${name}'s "${includeType}" include (${probe.status}). ${probe.text}`);
    const before = String(probe.text).replace(/\r\n/g, "\n");
    const after = replaceOnce(oldString, newString, name)(before, log);
    log.push(`Target: ${sourceUri}`);
    log.push(`Lines ${before.split("\n").length} -> ${after.split("\n").length}.`);

    // 2) lock the CLASS (locks are per top-level object, not per include)
    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      // 3) PUT to the include's OWN source uri, under the class's lock handle
      const sep = sourceUri.includes("?") ? "&" : "?";
      const put = await call(
        `${sourceUri}${sep}lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: after }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      // 4) unlock the CLASS
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    // 5) activate the CLASS (activation is always per top-level object)
    if (wrote && activate) await runActivation(call, uri, name, log, "class");
    else if (wrote) log.push("Not activated (activate=false) - activate it yourself or with activate_object.");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "update_class_include",
  "Overwrite the WHOLE source of a class's SEPARATE include - local types (CCIMP / 'Local Types' tab), " +
  "definitions, implementations, macros, or test classes - none of which live in /source/main " +
  "(update_class/patch_class cannot reach these). Run list_class_includes FIRST to get the exact includeType " +
  "string. Use this instead of patch_class_include when the include is empty/new (nothing to pattern-match " +
  "against) or you're replacing all of it. Locks the class, PUTs the whole new source to the discovered " +
  "include, unlocks, and optionally activates the class. Refuses to run on production profiles.",
  {
    className: z.string().describe("Class name, e.g. ZCL_ABL_PLANT_EMAIL"),
    includeType: z.string().describe("Exact includeType reported by list_class_includes for the include you want to write"),
    source: z.string().describe("Complete new source for this include - REPLACES its entire content"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate the class after writing. Default false."),
  },
  async ({ className, includeType, source, transport: corrNr, activate }) => {
    assertWritable();
    const name = className.toUpperCase();
    const uri = classUri(className);
    const host = profile().host;
    const log = [];

    const structXml = await adtGet(uri, "*/*");
    const includes = parseClassIncludes(structXml);
    const include = includes.find((i) => i.includeType.toLowerCase() === includeType.toLowerCase());
    if (!include) {
      const available = includes.map((i) => i.includeType || "(blank)").join(", ") || "(none found)";
      throw new Error(`No include of type "${includeType}" on ${name}. Available: ${available}. Run list_class_includes to check.`);
    }
    const sourceUri = classIncludeSourceUri(include, host, uri);
    if (!sourceUri) {
      throw new Error(
        `Found the "${includeType}" include on ${name} but its source link is ambiguous. ` +
        `Run list_class_includes to see its raw links and report this.`
      );
    }

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      return { ok: res.ok, status: res.status, text: await res.text() };
    };

    log.push(`Target: ${sourceUri}`);

    // 1) lock the CLASS (locks are per top-level object, not per include)
    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    let wrote = false;
    try {
      // 2) PUT the whole new source to the include's OWN source uri, under the class's lock handle
      const sep = sourceUri.includes("?") ? "&" : "?";
      const put = await call(
        `${sourceUri}${sep}lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: source }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);
      wrote = true;
    } finally {
      // 3) unlock the CLASS
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    // 4) activate the CLASS (activation is always per top-level object)
    if (wrote && activate) await runActivation(call, uri, name, log, "class");
    else if (wrote) log.push("Not activated (activate=false) - activate it yourself or with activate_object.");

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

server.tool(
  "update_class",
  "Overwrite the source of an EXISTING ABAP class. Locks, PUTs the whole new source, unlocks, then optionally " +
  "activates. Refuses to run on production profiles. IMPORTANT: this REPLACES the whole class - read it first " +
  "with get_object_info (.../source/main), edit that text, and send the complete result back (both the " +
  "DEFINITION and IMPLEMENTATION parts). Prefer patch_class for small edits.",
  {
    className: z.string().describe("Class name, e.g. ZCL_ABL_PLANT_EMAIL"),
    source: z.string().describe("Complete new ABAP source - REPLACES the entire class"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE24/ADT."),
  },
  async ({ className, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: className.toUpperCase(), uri: classUri(className),
      transform: wholeSource(source), corrNr, activate, kind: "class", createHint: "create_class",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_class",
  "Modify PART of an existing ABAP class without resending the whole source. Reads the current source, replaces " +
  "oldString with newString (must match EXACTLY ONCE), then locks, PUTs, unlocks, and optionally activates. " +
  "Prefer this over update_class for small edits like changing one method body. Refuses to run on production profiles.",
  {
    className: z.string().describe("Class name, e.g. ZCL_ABL_PLANT_EMAIL"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ className, oldString, newString, transport: corrNr, activate }) => {
    const name = className.toUpperCase();
    const text = await editSourceObject({
      name, uri: classUri(className),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "class", createHint: "create_class",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_bdef",
  "Overwrite the source of an EXISTING behavior definition (BDEF). Locks, PUTs the whole new source, unlocks, " +
  "then optionally activates. Refuses to run on production profiles. REPLACES the whole BDEF - read it first, " +
  "edit that text, and send the complete result back. Prefer patch_bdef for small edits.",
  {
    bdefName: z.string().describe("Behavior definition name = its root entity, e.g. ZTJI_PLANT_EMAIL"),
    source: z.string().describe("Complete new BDEF source - REPLACES the entire definition"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ bdefName, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: bdefName.toUpperCase(), uri: bdefUri(bdefName),
      transform: wholeSource(source), corrNr, activate, kind: "behavior definition", createHint: "create_bdef",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_bdef",
  "Modify PART of an existing behavior definition (BDEF) without resending the whole source. Reads the current " +
  "source, replaces oldString with newString (must match EXACTLY ONCE), then locks, PUTs, unlocks, and " +
  "optionally activates. Refuses to run on production profiles.",
  {
    bdefName: z.string().describe("Behavior definition name = its root entity, e.g. ZTJI_PLANT_EMAIL"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ bdefName, oldString, newString, transport: corrNr, activate }) => {
    const name = bdefName.toUpperCase();
    const text = await editSourceObject({
      name, uri: bdefUri(bdefName),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "behavior definition", createHint: "create_bdef",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_srvd",
  "Overwrite the source of an EXISTING service definition (SRVD). Locks, PUTs the whole new source, unlocks, " +
  "then optionally activates. Refuses to run on production profiles. REPLACES the whole definition - read it " +
  "first, edit that text, and send the complete result back. Prefer patch_srvd for small edits.",
  {
    srvdName: z.string().describe("Service definition name, e.g. ZTJ_UI_PLANT_EMAIL"),
    source: z.string().describe("Complete new SRVD source - REPLACES the entire definition"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ srvdName, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: srvdName.toUpperCase(), uri: srvdUri(srvdName),
      transform: wholeSource(source), corrNr, activate, kind: "service definition", createHint: "create_srvd",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_srvd",
  "Modify PART of an existing service definition (SRVD) without resending the whole source - e.g. exposing one " +
  "more entity. Reads the current source, replaces oldString with newString (must match EXACTLY ONCE), then " +
  "locks, PUTs, unlocks, and optionally activates. Refuses to run on production profiles.",
  {
    srvdName: z.string().describe("Service definition name, e.g. ZTJ_UI_PLANT_EMAIL"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false."),
  },
  async ({ srvdName, oldString, newString, transport: corrNr, activate }) => {
    const name = srvdName.toUpperCase();
    const text = await editSourceObject({
      name, uri: srvdUri(srvdName),
      transform: replaceOnce(oldString, newString, name), corrNr, activate, kind: "service definition", createHint: "create_srvd",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_function_module",
  "Overwrite the whole source of an EXISTING function module. Locks, PUTs, unlocks, then optionally activates. " +
  "Refuses to run on production profiles. REPLACES the entire FM (FUNCTION ... ENDFUNCTION.) - read it first and " +
  "send the complete result back. Prefer patch_function_module for small edits. Pass the group WITHOUT the SAPL prefix.",
  {
    functionGroup: z.string().describe("Function group WITHOUT the SAPL prefix, e.g. ZABLMM_QCF_WF"),
    functionModule: z.string().describe("Function module name, e.g. ZABLMM_QCF_WF_APPROVE"),
    source: z.string().describe("Complete new FM source - REPLACES the entire module"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE37."),
  },
  async ({ functionGroup, functionModule, source, transport: corrNr, activate }) => {
    const text = await editSourceObject({
      name: functionModule.toUpperCase(),
      uri: `/sap/bc/adt/functions/groups/${functionGroup.toLowerCase()}/fmodules/${functionModule.toLowerCase()}`,
      transform: wholeSource(source), corrNr, activate, kind: "function module", createHint: "create_function_module",
    });
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "patch_function_module",
  "Modify PART of an existing ABAP function module. Function-module source lives inside a function group, " +
  "so it must be locked/written through the fmodules URI - patch_program_source CANNOT do it (SAP rejects " +
  "locking L<GROUP>U<nn> as R3TR PROG). Reads the current source, replaces oldString with newString (must " +
  "match EXACTLY ONCE), then locks, PUTs, optionally activates, and unlocks. Refuses to run on production profiles. " +
  "Look up the group first if unsure: SELECT FUNCNAME, PNAME FROM TFDIR - PNAME 'SAPLZFOO' means group 'ZFOO'.",
  {
    functionGroup: z.string().describe("Function group WITHOUT the SAPL prefix, e.g. ZABLMM_QCF_WF"),
    functionModule: z.string().describe("Function module name, e.g. ZABLMM_QCF_WF_APPROVE"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request, e.g. D01K903896. Omit only for local/$TMP objects."),
    activate: z.boolean().optional().default(false).describe("Activate after writing. Default false - activate in SE37 yourself."),
  },
  async ({ functionGroup, functionModule, oldString, newString, transport: corrNr, activate }) => {
    assertWritable();

    if (!oldString) throw new Error("oldString must not be empty.");
    if (oldString === newString) throw new Error("oldString and newString are identical - nothing to do.");

    const grp = functionGroup.replace(/^SAPL/i, "").toLowerCase();
    const fm = functionModule.toLowerCase();
    const name = functionModule.toUpperCase();
    const uri = `/sap/bc/adt/functions/groups/${grp}/fmodules/${fm}`;
    const host = profile().host;
    const log = [];

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    let cookies = initialCookies;
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");

    const call = async (path, { method, headers = {}, body, accept = "*/*" }) => {
      const res = await fetch(`${host}${path}`, {
        method,
        headers: {
          ...authHeaders(accept),
          "X-CSRF-Token": token,
          "x-sap-adt-sessiontype": "stateful",
          Cookie: cookies,
          ...headers,
        },
        body,
        agent,
      });
      cookies = mergeCookies(cookies, res);
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    };

    const probe = await call(`${uri}/source/main`, { method: "GET", accept: "text/plain" });
    if (!probe.ok) {
      throw new Error(
        `Cannot read function module ${name} in group ${functionGroup.toUpperCase()} (${probe.status}). ` +
        `Check the group name - PNAME in TFDIR is SAPL<GROUP>. ${probe.text.slice(0, 400)}`
      );
    }

    // ADT hands source back with CRLF; callers naturally write LF.
    const nl = s => String(s).replace(/\r\n/g, "\n");
    let before = nl(probe.text);
    oldString = nl(oldString);
    newString = nl(newString);

    const hits = before.split(oldString).length - 1;
    if (hits === 0) {
      const firstLine = oldString.split("\n")[0];
      const near = before.split("\n").filter(l => firstLine.trim() && l.includes(firstLine.trim()));
      throw new Error(
        `oldString not found in ${name}. Nothing written.` +
        (near.length ? ` Lines containing the first line of oldString: ${JSON.stringify(near.slice(0, 5))}` : "")
      );
    }
    if (hits > 1) throw new Error(`oldString matched ${hits} times in ${name}. Nothing written. Add surrounding context to make it unique.`);
    const after = before.replace(oldString, newString);

    log.push(`Target: ${uri}`);
    log.push(`Patched 1 occurrence. Lines ${before.split("\n").length} -> ${after.split("\n").length}.`);

    const locked = await call(`${uri}?_action=LOCK&accessMode=MODIFY`, {
      method: "POST",
      accept: "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.Result",
    });
    if (!locked.ok) throw new Error(`Lock failed (${locked.status}). ${locked.text}`);
    const handle = (locked.text.match(/<LOCK_HANDLE>([^<]*)<\/LOCK_HANDLE>/) || [])[1];
    if (!handle) throw new Error(`No lock handle returned. ${locked.text}`);
    log.push("Locked.");

    try {
      const put = await call(
        `${uri}/source/main?lockHandle=${encodeURIComponent(handle)}` +
        (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : ""),
        { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: after }
      );
      if (!put.ok) throw new Error(`Source PUT failed (${put.status}). ${put.text}`);
      log.push(`Source written${corrNr ? ` on ${corrNr}` : ""}.`);

      if (activate) {
        const actBody =
          `<?xml version="1.0" encoding="UTF-8"?>\n` +
          `<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">\n` +
          `  <adtcore:objectReference adtcore:uri="${uri}" adtcore:name="${escapeXml(name)}"/>\n` +
          `</adtcore:objectReferences>`;
        const act = await call(`/sap/bc/adt/activation?method=activate&preauditRequests=false`, {
          method: "POST",
          headers: { "Content-Type": "application/xml" },
          body: actBody,
        });
        const msgs = parseActivationMessages(act.text);
        const bad = msgs.filter(m => /^[EAW]$/i.test(m.type));
        if (!act.ok || bad.length) {
          log.push(`ACTIVATION FAILED (HTTP ${act.status}) - source IS saved but the object is INACTIVE.`);
          for (const m of (bad.length ? bad : msgs)) log.push(`  [${m.type}] ${m.text}`);
          if (!bad.length) log.push(`  Raw response: ${(act.text || "(empty body)").slice(0, 1500)}`);
        } else {
          log.push("Activated cleanly.");
        }
      } else {
        log.push("Not activated (activate=false) - activate it in SE37.");
      }
    } finally {
      const unlocked = await call(`${uri}?_action=UNLOCK&lockHandle=${encodeURIComponent(handle)}`, {
        method: "POST",
      });
      log.push(unlocked.ok ? "Unlocked." : `WARNING: unlock failed (${unlocked.status}) - object may stay locked.`);
    }

    return { content: [{ type: "text", text: log.join("\n") }] };
  }
);

// --- BSP / UI5 repository files (MIME repository, NOT a normal ADT object) -
// A deployed UI5/Fiori app's webapp files (Component.js, views, controllers,
// manifest.json, ...) live in the BSP filestore, a completely separate ADT
// sub-tree from PROG/CLAS/CDS/etc: /sap/bc/adt/filestore/ui5-bsp/objects/...
// No create_*/update_*/patch_* tool above can reach these - confirmed by
// searching every declared collection, and verified against the open-source
// nwabap-ui5uploader deploy tool (github.com/nrdev88/nwabap-ui5uploader,
// lib/filestore.js), which this implementation mirrors:
//   - the BSP name + relative path are joined into ONE path segment and
//     percent-encoded together (a literal "/" inside becomes %2F)
//   - reading/writing a file's content is a plain GET/PUT on that segment
//     plus "/content" - unlike source objects, there is NO lock/unlock
//     ceremony at all; PUT instead sends "If-Match: *"
//   - listing a folder is a GET on its segment + "/content", returning an
//     Atom feed of <atom:entry> children (atom:category@term = folder/file)
const BSP_BASE = "/sap/bc/adt/filestore/ui5-bsp/objects";
const bspSegment = (bspName, relPath) =>
  encodeURIComponent(`${bspName.toUpperCase()}${relPath ? "/" + relPath.replace(/^\/+/, "") : ""}`);

server.tool(
  "list_bsp_files",
  "List the files/folders inside a deployed BSP/UI5 repository app (e.g. a Fiori app's webapp folder) - " +
  "read-only. Use this to find the exact relative path of a file before calling get_bsp_file/update_bsp_file. " +
  "This is a SEPARATE repository from PROG/CLAS/CDS - no other tool can browse it.",
  {
    bspName: z.string().describe("BSP application name, e.g. ZMMUIGRACCEPT"),
    folderPath: z.string().optional().describe("Relative folder path inside the app, e.g. webapp/controller. Omit for the root."),
  },
  async ({ bspName, folderPath }) => {
    const path = `${BSP_BASE}/${bspSegment(bspName, folderPath)}/content`;
    const xml = await adtGet(path, "application/atom+xml");
    const entries = [...xml.matchAll(/<atom:entry\b[^>]*>([\s\S]*?)<\/atom:entry>/g)].map(m => {
      const body = m[1];
      const id = (body.match(/<atom:id>([\s\S]*?)<\/atom:id>/) || [])[1] || "";
      const term = (body.match(/<atom:category[^>]*\bterm="([^"]*)"/) || [])[1] || "";
      const title = (body.match(/<atom:title[^>]*>([\s\S]*?)<\/atom:title>/) || [])[1] || "";
      return { name: decodeXml(title) || decodeXml(id), type: /folder/i.test(term) ? "folder" : "file" };
    }).filter(e => e.name);
    if (!entries.length) return { content: [{ type: "text", text: `No entries found under ${bspName}${folderPath ? "/" + folderPath : ""} (or the app doesn't exist).` }] };
    const lines = entries.map(e => `${e.type === "folder" ? "[dir] " : "      "}${e.name}`);
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "get_bsp_file",
  "Read the raw content of a single file inside a deployed BSP/UI5 repository app (e.g. Component.js, a " +
  "controller, manifest.json). Use list_bsp_files first to confirm the exact relative path. Read-only, safe " +
  "on any profile including production.",
  {
    bspName: z.string().describe("BSP application name, e.g. ZMMUIGRACCEPT"),
    filePath: z.string().describe("Relative file path inside the app, e.g. webapp/controller/Main.controller.js"),
  },
  async ({ bspName, filePath }) => {
    const path = `${BSP_BASE}/${bspSegment(bspName, filePath)}/content`;
    const text = await adtGet(path, "*/*");
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "update_bsp_file",
  "Overwrite the WHOLE content of an EXISTING file inside a deployed BSP/UI5 repository app. Unlike source " +
  "objects there is no lock/unlock step and no activation - the write takes effect immediately. Read the " +
  "file first with get_bsp_file, edit that text, and send the complete result back. Refuses to run on " +
  "production profiles.",
  {
    bspName: z.string().describe("BSP application name, e.g. ZMMUIGRACCEPT"),
    filePath: z.string().describe("Relative file path inside the app, e.g. webapp/controller/Main.controller.js"),
    content: z.string().describe("Complete new file content - REPLACES the whole file"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
  },
  async ({ bspName, filePath, content, transport: corrNr }) => {
    assertWritable();
    const host = profile().host;
    const path = `${BSP_BASE}/${bspSegment(bspName, filePath)}/content` +
      `?isBinary=false&charset=UTF-8` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : "");

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");
    const res = await fetch(`${host}${path}`, {
      method: "PUT",
      headers: {
        ...authHeaders("*/*"),
        "X-CSRF-Token": token,
        Cookie: initialCookies,
        "Content-Type": "application/octet-stream",
        "If-Match": "*",
      },
      body: content,
      agent,
    });
    if (!res.ok) throw new Error(`BSP file PUT failed (${res.status}). ${await res.text()}`);
    return { content: [{ type: "text", text: `Wrote ${content.length} bytes to ${bspName}/${filePath}${corrNr ? ` on ${corrNr}` : ""}. No activation needed.` }] };
  }
);

server.tool(
  "patch_bsp_file",
  "Modify PART of an existing BSP/UI5 repository file without resending the whole content. Reads the current " +
  "content, replaces oldString with newString (must match EXACTLY ONCE), then writes it back. Prefer this " +
  "over update_bsp_file for small edits. Refuses to run on production profiles.",
  {
    bspName: z.string().describe("BSP application name, e.g. ZMMUIGRACCEPT"),
    filePath: z.string().describe("Relative file path inside the app, e.g. webapp/controller/Main.controller.js"),
    oldString: z.string().describe("Exact existing text to replace. Must occur exactly once - include enough context to be unique."),
    newString: z.string().describe("Replacement text"),
    transport: z.string().optional().describe("Transport request. Omit only for local/$TMP objects."),
  },
  async ({ bspName, filePath, oldString, newString, transport: corrNr }) => {
    assertWritable();
    const host = profile().host;
    const contentPath = `${BSP_BASE}/${bspSegment(bspName, filePath)}/content`;

    const before = await adtGet(contentPath, "*/*");
    if (!oldString) throw new Error("oldString must not be empty.");
    const hits = before.split(oldString).length - 1;
    if (hits === 0) throw new Error(`oldString not found in ${bspName}/${filePath}. Nothing written.`);
    if (hits > 1) throw new Error(`oldString matched ${hits} times in ${bspName}/${filePath}. Nothing written. Add surrounding context to make it unique.`);
    const after = before.replace(oldString, newString);

    const { token, cookies: initialCookies } = await fetchCsrfToken();
    if (!token) throw new Error("Could not obtain a CSRF token - check credentials/profile.");
    const putPath = contentPath + `?isBinary=false&charset=UTF-8` + (corrNr ? `&corrNr=${encodeURIComponent(corrNr)}` : "");
    const res = await fetch(`${host}${putPath}`, {
      method: "PUT",
      headers: {
        ...authHeaders("*/*"),
        "X-CSRF-Token": token,
        Cookie: initialCookies,
        "Content-Type": "application/octet-stream",
        "If-Match": "*",
      },
      body: after,
      agent,
    });
    if (!res.ok) throw new Error(`BSP file PUT failed (${res.status}). ${await res.text()}`);
    return { content: [{ type: "text", text: `Patched 1 occurrence in ${bspName}/${filePath}${corrNr ? ` on ${corrNr}` : ""}. Lines ${before.split("\n").length} -> ${after.split("\n").length}. No activation needed.` }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
