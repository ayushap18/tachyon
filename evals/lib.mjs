// Shared by run.mjs and agent.mjs: CLI flags, provider resolution, the two
// request shapes the app uses (anthropic messages.create + OpenAI-compatible
// POST {base_url}/chat/completions), pacing/retry, pricing, JSON artifacts.
//
// SECURITY: key material is never printed, logged, or written anywhere — keys
// are used only in the Authorization header / SDK constructor.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export const DIR = new URL(".", import.meta.url).pathname;

const args = process.argv.slice(2);
export const flag = (f) => args.includes(f);
export const argValue = (f) => {
  const i = args.indexOf(f);
  return i >= 0 ? args[i + 1] : undefined;
};

// port of strip_fences in lib.rs: trim, strip a leading ```lang fence, strip trailing ```
export function stripFences(s) {
  return s
    .trim()
    .replace(/^```[a-z]*\s*/i, "")
    .replace(/(```)+$/, "")
    .trim();
}

// port of one_line in lib.rs: the app folds a multi-line model reply to one line before it
// reaches the pty (a newline there is an Enter), so the harness must score the same string.
export function oneLine(cmd) {
  return cmd
    .replace(/\\\r?\n/g, " ")
    .split(/\r\n|\r|\n/) // a bare CR is an Enter to the pty too
    .map((l) => l.replace(/\t/g, " ").replace(/\p{Cc}/gu, "").trim())
    .filter(Boolean)
    .join("; ");
}

export const sha256 = (s) => createHash("sha256").update(s).digest("hex");

// ---- provider resolution: ~/.config/tachyon/providers.json + env fallback ----
// Exits when nothing is benchmarkable; `keylessHint` names the caller's no-key mode.
export function loadProviders(keylessHint) {
  let config = {};
  try {
    config = JSON.parse(readFileSync(path.join(os.homedir(), ".config/tachyon/providers.json"), "utf8"));
  } catch {} // missing/malformed config is fine — env fallback may still apply
  const providers = Array.isArray(config.providers) ? config.providers : [];

  // Env fallback: fill missing keys (never overwrite config keys), synthesizing
  // the provider entry if the config lacks it entirely.
  const ENV_FALLBACKS = [
    {
      env: "GROQ_API_KEY",
      def: { id: "groq", kind: "openai", base_url: "https://api.groq.com/openai/v1", model: "openai/gpt-oss-120b" },
    },
    { env: "ANTHROPIC_API_KEY", def: { id: "claude", kind: "anthropic", model: "claude-opus-4-8" } },
  ];
  for (const { env, def } of ENV_FALLBACKS) {
    const envKey = process.env[env];
    if (!envKey) continue;
    const existing = providers.find((p) => p.id === def.id);
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
  const only = argValue("--provider");
  if (only) bench = bench.filter((p) => p.id === only);
  // --model: benchmark a provider against a model other than the one the app is
  // configured with (copied, so the config object is untouched). One provider
  // only — a model id means nothing across providers.
  const model = argValue("--model");
  if (model && !only) {
    console.error("--model needs --provider");
    process.exit(1);
  }
  if (model) bench = bench.map((p) => ({ ...p, model }));

  if (bench.length === 0) {
    console.error(
      "No providers with keys to benchmark.\n" +
        "Configure keys in-app (/key <id> <apikey>), or set GROQ_API_KEY / ANTHROPIC_API_KEY.\n" +
        keylessHint,
    );
    process.exit(1);
  }
  return bench;
}

// ---- request dispatch ----
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const anthropicClients = new Map(); // provider id → SDK client, kept off provider objects

async function ask(p, system, prompt) {
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
      // no `temperature` here: current Claude models reject it with a 400
      msg = await client.messages.create({
        model: p.model,
        max_tokens: 1024,
        system,
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
    signal: AbortSignal.timeout(120000), // a hung socket would otherwise stall the whole run
    body: JSON.stringify({
      model: p.model,
      max_tokens: 1024,
      temperature: 0, // run-to-run diffs should mean the prompt or model changed, not the dice
      messages: [
        { role: "system", content: system },
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

// Pace request starts to stay under free-tier RPM limits (Groq free tier ~30/min).
// Global token-bucket-ish gate; --rpm overrides. This caps the effective rate regardless
// of pool concurrency, which prevents the 429 storms that otherwise wreck the numbers.
const MIN_INTERVAL = 60000 / (Number(argValue("--rpm")) || 28);
let nextSlot = 0;
async function pace() {
  const now = Date.now();
  const wait = Math.max(0, nextSlot - now);
  nextSlot = Math.max(now, nextSlot) + MIN_INTERVAL;
  if (wait) await sleep(wait);
}

const MAX_RETRIES = 5;

// → { text (raw), ms, usage }
export async function generate(p, system, prompt) {
  // On 429, honor retry-after (or exponential backoff) and retry up to MAX_RETRIES.
  // Free-tier rate limits are measurement noise, not model failures — don't let them
  // count as errors until we've genuinely exhausted retries.
  for (let attempt = 0; ; attempt++) {
    try {
      await pace();
      return await ask(p, system, prompt);
    } catch (e) {
      if (e.message === "429" && attempt < MAX_RETRIES) {
        await sleep(Math.max(e.retryAfter ?? 0, 2 ** attempt) * 1000);
        continue;
      }
      throw e;
    }
  }
}

// ponytail: index-sharing worker pool, no queue lib. Default 2 to stay under free-tier RPM;
// override with --concurrency N.
export async function pool(items, worker, size = Number(argValue("--concurrency")) || 2) {
  let i = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (i < items.length) await worker(items[i++]);
    }),
  );
}

// Approximate $/1M tokens [input, output], keyed by MODEL id (a provider can be
// pointed at any model) — a snapshot; prices drift. Unknown models cost "—".
const PRICES = {
  "claude-opus-5": [5, 25],
  "claude-opus-4-8": [5, 25],
  "claude-sonnet-5": [2, 10],
  "claude-haiku-4-5": [1, 5],
  "gpt-4o": [2.5, 10],
  "gemini-2.0-flash": [0.1, 0.4],
  "deepseek-chat": [0.27, 1.1],
  "mistral-large-latest": [2, 6],
  "moonshot-v1-8k": [0.6, 2.5],
};

// USD, or null when the model is unpriced or the provider reported no usage
export function costUsd(model, tokensIn, tokensOut) {
  const price = PRICES[model];
  return price && (tokensIn || tokensOut) ? (tokensIn / 1e6) * price[0] + (tokensOut / 1e6) * price[1] : null;
}
export const usd = (v) => (v == null ? "—" : `$${v.toFixed(4)}`);
export const pct = (n, d) => (d === 0 ? "—" : `${((100 * n) / d).toFixed(1)}% (${n}/${d})`);

// A run where every request failed measured the network or the config, not the
// model: say so and fail, rather than let "0.0%" be read (or --written) as a score.
export function failIfAllErrored(id, errors, total) {
  if (total === 0 || errors < total) return false;
  console.error(`\nNO RESULT for ${id}: all ${total} requests failed — this is a provider/config failure, not a model score`);
  process.exitCode = 1;
  return true;
}

// evals/results/<ISO-timestamp>-<name>.json (gitignored; copy one into
// evals/baseline/ to commit it). ":" → "-" keeps the name portable.
export function writeArtifact(name, data) {
  mkdirSync(DIR + "results", { recursive: true });
  const at = new Date().toISOString();
  const file = `${DIR}results/${at.replace(/:/g, "-")}-${name}.json`;
  writeFileSync(file, JSON.stringify({ at, ...data }, null, 2) + "\n");
  console.error(`wrote ${path.relative(process.cwd(), file)}`);
}
