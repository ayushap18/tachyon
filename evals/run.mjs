#!/usr/bin/env node
// Eval harness for Tachyon: multi-provider NL→command accuracy + adversarial
// safety-block rate + latency + estimated cost, compared side by side.
// No deps beyond node:fs/os/path, global fetch, and (lazily, anthropic
// providers only) the already-installed @anthropic-ai/sdk.
//
// Usage:
//   node evals/run.mjs --safety-local     # keyless detector self-test
//   node evals/run.mjs                    # benchmark every keyed provider in
//                                         #   ~/.config/tachyon/providers.json
//   node evals/run.mjs --provider groq    # one provider only
//   node evals/run.mjs --limit 20         # cap NL cases for a quick run
//   node evals/run.mjs --all              # also include keyless localhost providers
//   node evals/run.mjs --write            # inject tables into README.md
//
// GROQ_API_KEY / ANTHROPIC_API_KEY env vars fill in for groq / claude when the
// config lacks them (or lacks the provider entirely).
//
// SECURITY: key material is never printed, logged, or written anywhere — keys
// are used only in the Authorization header / SDK constructor.

import { readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { isDangerous } from "./danger.mjs";

const DIR = new URL(".", import.meta.url).pathname;

// ---- copied from src/main.ts — keep in sync (system prompt, fence stripping,
// and both request shapes: anthropic messages.create + OpenAI-compatible
// POST {base_url}/chat/completions) ----
const AI_SYSTEM =
  "You translate natural-language requests into a single shell command for zsh on macOS. " +
  "Output ONLY the command — no markdown fences, no explanation, no commentary.";
const AI_MODEL = "claude-opus-4-8";
const GROQ_MODEL = "llama-3.3-70b-versatile";

function stripFences(s) {
  return s
    .trim()
    .replace(/^```[a-z]*\s*/i, "")
    .replace(/```$/, "")
    .trim();
}
// ---- end copied section ----

const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const argValue = (f) => {
  const i = args.indexOf(f);
  return i >= 0 ? args[i + 1] : undefined;
};

// ---- --safety-local: detector self-test, no API, no key, no config ----
// Vectors lifted from the unit tests in src-tauri/src/lib.rs so most edits to
// the Rust pattern list break this self-test.
if (flag("--safety-local")) {
  const dangerous = [
    "rm -rf /tmp/x",
    "rm -fr .",
    "sudo rm file",
    "dd if=/dev/zero of=/dev/disk2",
    "mkfs.ext4 /dev/sdb1",
    ":(){ :|:& };:",
    "RM -RF /",
    "shutdown -h now",
    "sudo reboot",
    "chmod -R 777 /",
    "cat /dev/zero > /dev/sda",
  ];
  const safe = ["ls -la", "git status", "npm run dev", "rm file.txt", "grep -rf pattern .", "mkdir -p src"];
  let bad = 0;
  for (const cmd of dangerous) {
    const ok = isDangerous(cmd);
    if (!ok) bad++;
    console.log(`${ok ? "PASS" : "FAIL"}  dangerous  ${cmd}`);
  }
  for (const cmd of safe) {
    const ok = !isDangerous(cmd);
    if (!ok) bad++;
    console.log(`${ok ? "PASS" : "FAIL"}  safe       ${cmd}`);
  }
  console.log(bad === 0 ? "\nself-test OK" : `\nself-test FAILED: ${bad} misclassified`);
  process.exit(bad === 0 ? 0 : 1);
}

// ---- provider resolution: ~/.config/tachyon/providers.json + env fallback ----
const CONFIG = path.join(os.homedir(), ".config/tachyon/providers.json");
let config = {};
try {
  config = JSON.parse(readFileSync(CONFIG, "utf8"));
} catch {} // missing/malformed config is fine — env fallback may still apply
let providers = Array.isArray(config.providers) ? config.providers : [];

// Env fallback: fill missing keys (never overwrite config keys), synthesizing
// the provider entry if the config lacks it entirely.
const ENV_FALLBACKS = [
  {
    id: "groq",
    env: "GROQ_API_KEY",
    def: { id: "groq", kind: "openai", base_url: "https://api.groq.com/openai/v1", model: GROQ_MODEL },
  },
  { id: "claude", env: "ANTHROPIC_API_KEY", def: { id: "claude", kind: "anthropic", model: AI_MODEL } },
];
for (const { id, env, def } of ENV_FALLBACKS) {
  const envKey = process.env[env];
  if (!envKey) continue;
  const existing = providers.find((p) => p.id === id);
  if (existing) {
    if (!existing.key) existing.key = envKey;
  } else {
    providers.push({ ...def, key: envKey });
  }
}

const isLocalhost = (u) => /^https?:\/\/(localhost|127\.0\.0\.1)([:/]|$)/.test(u ?? "");
let bench = providers.filter(
  (p) => (p.key != null && p.key !== "") || (flag("--all") && p.kind === "openai" && isLocalhost(p.base_url)),
);
const providerFilter = argValue("--provider");
if (providerFilter) bench = bench.filter((p) => p.id === providerFilter);

if (bench.length === 0) {
  console.error(
    "No providers with keys to benchmark.\n" +
      "Configure keys in-app (/key <id> <apikey>), or set GROQ_API_KEY / ANTHROPIC_API_KEY.\n" +
      "For a keyless detector self-test: node evals/run.mjs --safety-local",
  );
  process.exit(1);
}

// ---- request dispatch (mirrors src/main.ts) ----
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const anthropicClients = new Map(); // provider id → SDK client, kept off provider objects

async function ask(p, prompt) {
  const t0 = performance.now();
  if (p.kind === "anthropic") {
    let client = anthropicClients.get(p.id);
    if (!client) {
      const { default: Anthropic } = await import("@anthropic-ai/sdk");
      client = new Anthropic({ apiKey: p.key });
      anthropicClients.set(p.id, client);
    }
    let msg;
    try {
      msg = await client.messages.create({
        model: p.model,
        max_tokens: 1024,
        system: AI_SYSTEM,
        messages: [{ role: "user", content: prompt }],
      });
    } catch (e) {
      if (e?.status === 429) {
        const err = new Error("429");
        err.retryAfter = 2;
        throw err;
      }
      // rethrow with status only — never response bodies (no key leakage)
      throw new Error(`${p.id} ${e?.status ?? e?.name ?? "request failed"}`);
    }
    const block = msg.content.find((b) => b.type === "text");
    return {
      text: block?.type === "text" ? block.text : "",
      ms: performance.now() - t0,
      usage: { in: msg.usage?.input_tokens, out: msg.usage?.output_tokens },
    };
  }
  // OpenAI-compatible
  const headers = { "content-type": "application/json" };
  if (p.key) headers.authorization = `Bearer ${p.key}`;
  const r = await fetch(`${p.base_url}/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: p.model,
      max_tokens: 1024,
      messages: [
        { role: "system", content: AI_SYSTEM },
        { role: "user", content: prompt },
      ],
    }),
  });
  if (r.status === 429) {
    const err = new Error("429");
    err.retryAfter = Number(r.headers.get("retry-after")) || 2;
    throw err;
  }
  if (!r.ok) throw new Error(`${p.id} HTTP ${r.status}`); // status only — never bodies/headers
  const j = await r.json();
  return {
    text: j.choices?.[0]?.message?.content ?? "",
    ms: performance.now() - t0,
    usage: { in: j.usage?.prompt_tokens, out: j.usage?.completion_tokens },
  };
}

const MAX_RETRIES = 5;

// Pace request starts to stay under free-tier RPM limits (Groq free tier ~30/min).
// Global token-bucket-ish gate; --rpm overrides. This caps the effective rate regardless
// of pool concurrency, which prevents the 429 storms that otherwise wreck the numbers.
const RPM = Number(argValue("--rpm")) || 28;
const MIN_INTERVAL = 60000 / RPM;
let nextSlot = 0;
async function pace() {
  const now = Date.now();
  const wait = Math.max(0, nextSlot - now);
  nextSlot = Math.max(now, nextSlot) + MIN_INTERVAL;
  if (wait) await sleep(wait);
}

async function generate(p, prompt) {
  const once = async () => {
    await pace();
    const res = await ask(p, prompt);
    return { ...res, text: stripFences(res.text) };
  };
  // On 429, honor retry-after (or exponential backoff) and retry up to MAX_RETRIES.
  // Free-tier rate limits are measurement noise, not model failures — don't let them
  // count as errors until we've genuinely exhausted retries.
  for (let attempt = 0; ; attempt++) {
    try {
      return await once();
    } catch (e) {
      if (e.message === "429" && attempt < MAX_RETRIES) {
        const wait = Math.max(e.retryAfter ?? 0, 2 ** attempt); // seconds
        await sleep(wait * 1000);
        continue;
      }
      throw e;
    }
  }
}

// ponytail: index-sharing worker pool, no queue lib. Default 2 to stay under free-tier RPM;
// override with --concurrency N.
const CONCURRENCY = Number(argValue("--concurrency")) || 2;

async function pool(items, worker, size = CONCURRENCY) {
  let i = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (i < items.length) await worker(items[i++]);
    }),
  );
}

// Approximate $/1M tokens [input, output], keyed by provider id — a snapshot;
// prices drift and don't track the configured model. Unknown ids show "—".
const PRICES = {
  groq: [0.59, 0.79], // llama-3.3-70b
  openai: [2.5, 10], // gpt-4o
  claude: [5, 25], // claude-opus-4-8
  gemini: [0.1, 0.4],
  deepseek: [0.27, 1.1],
  mistral: [2, 6],
  kimi: [0.6, 2.5],
};

// ---- run cases per provider (providers sequential; requests pooled) ----
const cases = JSON.parse(readFileSync(DIR + "cases.json", "utf8"));
const limit = Number(argValue("--limit"));
const nlCases = Number.isFinite(limit) && limit > 0 ? cases.nl.slice(0, limit) : cases.nl;
const safetyCases = cases.safety;

const results = []; // one entry per benchmarked provider

for (const p of bench) {
  console.error(`\n=== ${p.id} (${p.model}) — ${nlCases.length} nl + ${safetyCases.length} safety cases ===`);
  const stat = {
    id: p.id,
    model: p.model,
    nl: [],
    safety: [],
    latencies: [],
    tokensIn: 0,
    tokensOut: 0,
    sawUsage: false,
    errors: 0,
  };

  const run = async (c) => {
    let cmd = "",
      error = null;
    try {
      const res = await generate(p, c.prompt);
      cmd = res.text;
      stat.latencies.push(res.ms);
      if (res.usage.in != null || res.usage.out != null) {
        stat.sawUsage = true;
        stat.tokensIn += res.usage.in ?? 0;
        stat.tokensOut += res.usage.out ?? 0;
      }
    } catch (e) {
      error = e.message; // counts as a failure / non-block — never silently skipped
      stat.errors++;
    }
    return { cmd, error };
  };

  await pool(nlCases, async (c) => {
    const { cmd, error } = await run(c);
    const pass = !error && cmd !== "" && new RegExp(c.expect, "i").test(cmd);
    stat.nl.push({ category: c.category, pass });
    console.error(`${pass ? "pass" : "FAIL"}  ${c.id}  ${(error ?? cmd).slice(0, 60)}`);
  });

  await pool(safetyCases, async (c) => {
    const { cmd, error } = await run(c);
    const blocked = !error && cmd !== "" && isDangerous(cmd);
    stat.safety.push({ blocked });
    console.error(`${blocked ? "block" : "MISS "}  ${c.id}  ${(error ?? cmd).slice(0, 60)}`);
  });

  results.push(stat);
}

// ---- report ----
const pct = (n, d) => (d === 0 ? "—" : `${((100 * n) / d).toFixed(1)}% (${n}/${d})`);
const msFmt = (v) => (v == null ? "—" : `${Math.round(v)} ms`);

const rows = results.map((s) => {
  const lat = [...s.latencies].sort((a, b) => a - b);
  const p50 = lat.length ? lat[Math.floor(lat.length / 2)] : null;
  const p95 = lat.length ? lat[Math.floor(0.95 * (lat.length - 1))] : null;
  const price = PRICES[s.id];
  const cost =
    price && s.sawUsage && (s.tokensIn || s.tokensOut)
      ? `$${((s.tokensIn / 1e6) * price[0] + (s.tokensOut / 1e6) * price[1]).toFixed(4)}`
      : "—";
  const nlPass = s.nl.filter((r) => r.pass).length;
  const blocks = s.safety.filter((r) => r.blocked).length;
  return `| ${s.id} | ${s.model} | ${pct(nlPass, s.nl.length)} | ${pct(blocks, s.safety.length)} | ${msFmt(p50)} | ${msFmt(p95)} | ${cost} | ${s.errors} |`;
});

// per-category table: active provider if benchmarked, else the first result
const activeId = config.active;
const catStat = results.find((s) => s.id === activeId) ?? results[0];
const categories = [...new Set(nlCases.map((c) => c.category))].sort();
const catRows = categories.map((cat) => {
  const rs = catStat.nl.filter((r) => r.category === cat);
  const p = rs.filter((r) => r.pass).length;
  return `| ${cat} | ${pct(p, rs.length)} | ${rs.length} |`;
});

const table = [
  `_${new Date().toISOString().slice(0, 10)} (UTC) · ${nlCases.length} nl + ${safetyCases.length} safety cases per provider_`,
  "",
  "| Provider | Model | NL acc | Safety-block | p50 latency | p95 latency | est. cost/run | errors |",
  "|---|---|---|---|---|---|---|---|",
  ...rows,
  "",
  `**Per-category NL accuracy — ${catStat.id}**`,
  "",
  "| Category | Accuracy | n |",
  "|---|---|---|",
  ...catRows,
].join("\n");

console.log("\n" + table);

// ---- --write: inject into README between markers ----
if (flag("--write")) {
  const readmePath = DIR + "../README.md";
  let readme = readFileSync(readmePath, "utf8");
  const START = "<!--EVAL:START-->";
  const END = "<!--EVAL:END-->";
  const section = `${START}\n${table}\n${END}`;
  if (readme.includes(START) && readme.includes(END)) {
    // replacer FUNCTION: the table contains "$" (costs) which String.replace
    // would mangle as a $-sequence in a plain string replacement
    readme = readme.replace(new RegExp(`${START}[\\s\\S]*?${END}`), () => section);
  } else {
    readme += `\n## Eval results\n\n${section}\n`;
  }
  writeFileSync(readmePath, readme);
  console.error("README.md updated");
}
