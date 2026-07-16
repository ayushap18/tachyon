export const meta = {
  name: 'tachyon-nl-to-command',
  description: 'Plan, build, and test-fix-loop the natural language → command AI feature',
  phases: [
    { title: 'Plan', detail: 'read repo, produce implementation plan' },
    { title: 'Build', detail: 'implement AI command bar + safety detector' },
    { title: 'Test', detail: 'cargo test + check + tsc + vite build' },
    { title: 'Fix', detail: 'repair errors, then retest' },
  ],
}

const REPO = '/Users/ayush18/tachyon'

const SPEC = `
Feature: natural language → shell command (the first AI feature) for Tachyon, repo at ${REPO}.
Tauri 2 app. Rust backend src-tauri/src/lib.rs has: PtyState, pty_spawn/pty_write/pty_resize, get_context
(returns {cwd, branch, dirty, shell_pid}), plus #[cfg(test)] tests. Frontend src/main.ts: xterm.js Terminal,
FitAddon, settings panel (theme/font/size persisted in localStorage as 'tachyon-settings'), status bar,
pty bridge. index.html has #terminal, #status-bar, #settings-btn, #settings.

Requirements:

1. npm dep: add @anthropic-ai/sdk (the ONLY new dep — no zod, nothing else). Frontend calls Claude
   directly from the webview: new Anthropic({ apiKey, dangerouslyAllowBrowser: true }).
   Model: "claude-opus-4-8" as a const. Non-streaming messages.create, max_tokens: 1024, NO thinking
   param, NO temperature (rejected on this model). System prompt instructs: output ONLY the shell
   command, no markdown fences, no explanation; target shell is zsh on macOS.

2. API key resolution, in order: (a) settings.apiKey from localStorage (add a password-type input
   labeled "API key" to the existing settings panel), (b) ANTHROPIC_API_KEY env var — expose via a
   trivial Rust command get_env_api_key() -> Option<String> reading std::env::var. Resolve once at
   AI-bar-open time. If neither present, the AI bar shows "Set API key in settings (⌘,)" instead of querying.

3. AI command bar UI: Cmd+K toggles a slim input bar docked directly above the status bar
   (index.html: <div id="ai-bar" hidden><span id="ai-icon">✦</span><input id="ai-input"
   placeholder="Describe a command…"><span id="ai-status"></span></div>). Esc closes and refocuses the
   terminal. Enter: sets ai-status to "thinking…", calls Claude with a user message containing the
   request plus context: cwd + git branch/dirty from invoke("get_context"), and the last ~30 non-empty
   lines of the terminal buffer (read via term.buffer.active, translateToString(true), trimmed).
   On response: strip whitespace/backtick fences, then invoke pty_write with the command text WITHOUT
   a trailing newline — it appears typed at the shell prompt for the user to review and run themselves.
   Never auto-execute. Close the bar and focus the terminal after inserting. On API error, show the
   error message in ai-status (stay open).

4. Safety detector in Rust (the trust boundary — it will be reused by future agent mode):
   pub fn is_dangerous(cmd: &str) -> bool, plus tauri command check_dangerous(cmd) -> bool.
   Case-insensitive detection of at least: rm -rf / rm -fr (any path), sudo rm, dd of=/dev/,
   mkfs, shutdown/reboot, git push --force / -f to protected-looking refs is NOT needed — keep list tight:
   rm -rf|-fr, sudo rm, dd of=/dev, mkfs, > /dev/sd, chmod -R 777 /, :(){ fork bomb pattern ":(){",
   shutdown, reboot. Before inserting a generated command the frontend calls check_dangerous; if true,
   style the AI bar red (class "danger") and show "⚠ destructive — review carefully" in ai-status, still
   insert the text (it is never executed automatically).

5. Rust unit tests (#[cfg(test)]): is_dangerous positive cases (rm -rf /tmp/x, sudo rm file, dd
   of=/dev/disk2, mkfs.ext4, fork bomb, RM -RF caps) and negative cases (ls -la, rm file.txt,
   grep -rf pattern ., echo "rm -rf", git commit -m "remove rm -rf docs" is ALLOWED to false-positive —
   don't over-engineer substring matching; pick negatives that must pass: ls, git status, npm run dev,
   rm single-file). Keep the implementation a simple lowercase substring/pattern scan — no regex crate.

6. CSS: style #ai-bar to match the app (dark, like #status-bar but with an accent border-top;
   .danger state = red border/text). Body is flex column: ai-bar sits between #terminal and #status-bar;
   fit.fit() must be called when the bar opens/closes so the terminal reflows (it changes layout height).

7. Minimal diffs, match existing style, don't refactor unrelated code, don't touch README.
`

phase('Plan')
const plan = await agent(
  `You are planning a feature. Read these files in ${REPO}: src-tauri/src/lib.rs, src/main.ts,
index.html, src/styles.css, package.json, src-tauri/tauri.conf.json (check CSP — if "csp" is not null,
api.anthropic.com must be allowed in connect-src; flag it). Then produce a precise plan for:
${SPEC}
Return per-file changes with signatures, the exact danger-pattern list, and risks (CSP blocking fetch,
dangerouslyAllowBrowser requirement, xterm buffer API shape, layout/fit interactions, focus handling).`,
  {
    label: 'plan:nl-to-command',
    schema: {
      type: 'object',
      required: ['summary', 'files', 'risks'],
      properties: {
        summary: { type: 'string' },
        files: {
          type: 'array',
          items: {
            type: 'object',
            required: ['path', 'changes'],
            properties: { path: { type: 'string' }, changes: { type: 'string' } },
          },
        },
        risks: { type: 'array', items: { type: 'string' } },
      },
    },
  },
)

phase('Build')
await agent(
  `Implement this feature in ${REPO} by editing files directly (run npm install for the new dep). Spec:
${SPEC}
Plan (follow unless it contradicts the spec or the actual code):
${JSON.stringify(plan, null, 2)}
Before finishing run: cd ${REPO} && npx tsc --noEmit, and
source $HOME/.cargo/env && cd ${REPO}/src-tauri && cargo check 2>&1 | tail -5 — fix what you can.
Return a one-paragraph summary of changes.`,
  { label: 'build:nl-to-command' },
)

const TEST_SCHEMA = {
  type: 'object',
  required: ['passed', 'errors'],
  properties: {
    passed: { type: 'boolean', description: 'true only if ALL checks pass' },
    errors: { type: 'string', description: 'verbatim error output, empty if passed' },
  },
}

const testPrompt = `Run ALL of these checks in ${REPO} and report honestly:
1. source $HOME/.cargo/env && cd ${REPO}/src-tauri && cargo test 2>&1 | tail -25
2. cd ${REPO}/src-tauri && cargo check 2>&1 | tail -10
3. cd ${REPO} && npx tsc --noEmit
4. cd ${REPO} && npm run build 2>&1 | tail -10
5. grep -q '"@anthropic-ai/sdk"' ${REPO}/package.json && echo "sdk dep OK" || echo "sdk dep MISSING"
passed=true ONLY if: all cargo tests pass, cargo check clean, tsc exits 0, vite build succeeds, sdk dep present.
Include verbatim failing output in errors. Do NOT fix anything — test and report only.`

let result = null
for (let round = 1; round <= 5; round++) {
  result = await agent(testPrompt, { label: `test:round${round}`, phase: 'Test', schema: TEST_SCHEMA })
  if (result.passed) break
  log(`Round ${round}: failures found, dispatching fixer`)
  await agent(
    `Fix these build/test errors in ${REPO}. Feature spec for context:
${SPEC}
Errors:
${result.errors}
Make the minimal fix for each. Re-run the failing check yourself to confirm before finishing.`,
    { label: `fix:round${round}`, phase: 'Fix' },
  )
}

return {
  plan: plan.summary,
  risks: plan.risks,
  passed: result.passed,
  remainingErrors: result.passed ? '' : result.errors,
}