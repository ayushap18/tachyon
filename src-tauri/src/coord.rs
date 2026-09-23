//! The shared boards: a message board and a task board for agents that share one terminal.
//!
//! Deliberately the dullest module in the tree. No Tauri type, no app handle, no runtime, no
//! static, and no I/O beyond `read_config`/`write_config` — every mutation is a plain method
//! on `&mut Board` that takes the ACTOR'S NAME as a `&str`. The server resolves the bearer
//! token to a `Caller` and hands over `caller.name`, so nothing here can be confused about
//! who is asking and nothing here ever sees a token. The lock is the server's; every method
//! below is straight-line, so a caller cannot hold that lock across a suspension point.
//!
//! The board is an agent-to-agent channel by construction: anything one agent writes lands in
//! another's context. It is bounded, validated and attributed, and that is all it is — the
//! human's keypress is still what stands between a message and the shell.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Messages live in memory only, so the ring is the whole retention policy: a slow reader is
/// told exactly how many it lost (`missed`) rather than handed a silent gap.
const MESSAGE_RING: usize = 500;
/// Active means open or claimed. The ceiling is a human's: a board with more than this much
/// unfinished work on it is not being read by anyone.
const MAX_ACTIVE_TASKS: usize = 64;
/// Including finished ones, which stay as the record of what was done until evicted.
const MAX_TASKS: usize = 256;
/// A task is handed out at most this many times. Only a restart re-opens a claimed task, so
/// reaching this means three holders died on it: the fourth agent is not sent in after them.
const MAX_CLAIMS: u32 = 3;
/// `run_command` proposals one task may raise (its `task_id`). A task is a unit of work a
/// human will be asked to approve, so an agent looping on one stops reaching the bar at 20.
const MAX_TASK_PROPOSALS: u32 = 20;
/// pub(crate) because the tool schema publishes it as `maxLength`: the cap a client is told
/// about and the cap that refuses it must be one number.
pub(crate) const MAX_MESSAGE_CHARS: usize = 4000;
// pub(crate) for the same reason as MAX_MESSAGE_CHARS: the task tools' `maxLength`.
pub(crate) const MAX_TITLE_CHARS: usize = 200;
pub(crate) const MAX_DETAIL_CHARS: usize = 4000;
/// `parse_agent_name`'s ceiling: a name longer than that can never match a registered agent.
pub(crate) const MAX_NAME_CHARS: usize = 32;

/// The answer for a task the caller may not touch AND for one that does not exist. Ownership
/// must not be an oracle: an agent cannot use the error to learn that someone else's task is
/// there (R20).
const NO_SUCH_TASK: &str = "no such task";

/// THE validator for every string that reaches a board, and the same refusals as the approval
/// bar's (`parse_run_args`): control characters, bidi overrides and the other invisibles,
/// empty, and a per-field length cap. A board entry is rendered in one row for the human and
/// pasted into another agent's context, and a newline or an RLO in either is how one agent
/// forges a line that neither of them wrote. Refused outright, never cleaned up: unlike a
/// model's reply, an external client can be told no.
pub(crate) fn validate_text(field: &str, raw: &str, max: usize) -> Result<String, String> {
    if raw.chars().any(|c| c.is_control() || crate::is_invisible(c)) {
        return Err(format!("`{field}` contains control or bidi-override characters"));
    }
    let text = raw.trim();
    if text.is_empty() {
        return Err(format!("`{field}` is empty"));
    }
    if text.chars().count() > max {
        return Err(format!("`{field}` is longer than {max} characters"));
    }
    Ok(text.to_string())
}

/// `validate_text`, and no run of 64 hex characters. That is exactly what an agent's bearer
/// token looks like, and redaction cannot tell one from a sha256sum, so it leaves both alone;
/// but task text is listed to every agent and its title crosses IPC in `hub_state`. A hash
/// is still namable by a prefix of it.
fn validate_task_text(field: &str, raw: &str, max: usize) -> Result<String, String> {
    let text = validate_text(field, raw, max)?;
    if text.as_bytes().split(|c| !c.is_ascii_hexdigit()).any(|run| run.len() >= 64) {
        return Err(format!("`{field}` holds a 64-character hex string, the shape of a token \u{2014} name it by a prefix"));
    }
    Ok(text)
}

pub(crate) struct Message {
    /// Monotonic across the whole board and never reused, so a reader's cursor is a single
    /// number and a gap in it is detectable.
    pub(crate) seq: u64,
    /// The caller's name, from the bearer. There is no argument that can set this.
    pub(crate) from: String,
    /// Addressing, not confidentiality: every registered agent reads the whole board. Agents
    /// that share one terminal share one human, so there is nothing to keep between them.
    pub(crate) to: Option<String>,
    pub(crate) text: String,
}

impl Message {
    pub(crate) fn id(&self) -> String {
        format!("m_{}", self.seq)
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskState {
    #[default]
    Open,
    Claimed,
    Done,
    Failed,
    Cancelled,
}

impl TaskState {
    /// Terminal = nobody is expected to touch it again. Only these three may be set by
    /// `update_task`, and only a terminal task may be evicted to make room.
    pub(crate) fn is_terminal(self) -> bool {
        !matches!(self, TaskState::Open | TaskState::Claimed)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            TaskState::Open => "open",
            TaskState::Claimed => "claimed",
            TaskState::Done => "done",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
        }
    }
}

/// ON-DISK SHAPE, frozen at v1: every field here is written to `tasks.json` and read back by
/// builds that do not know about anything added later, which is why the struct is
/// `serde(default)` — a missing field is that field's default, not a corrupt file.
// Debug is safe here and nowhere near `AgentToken`: a task carries agent-authored text only,
// never a token.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Task {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) detail: Option<String>,
    /// Who created it. Keeps the right to cancel even after someone else claims it.
    pub(crate) creator: String,
    /// Settable ONLY by the creator at creation: a worker cannot hand its work to another
    /// agent. Advisory on an agent's task — the board suggests who should take it, it does not
    /// bind anyone to it — and binding on the manager's (see `claim`).
    pub(crate) assignee: Option<String>,
    pub(crate) state: TaskState,
    pub(crate) holder: Option<String>,
    /// How many times this task has EVER been claimed. A restart re-opens a claimed task
    /// without touching this, so a crashed holder does not burn a claim, while a task that
    /// keeps killing its holder stops being handed out (`MAX_CLAIMS`).
    pub(crate) claims: u32,
    /// Whatever the holder said when finishing it.
    pub(crate) note: Option<String>,
    /// Proposals raised against this task so far — see `MAX_TASK_PROPOSALS`. Added after v1
    /// shipped its first field list; `serde(default)` reads an older file as zero.
    pub(crate) proposals: u32,
}

#[derive(Default)]
pub(crate) struct Board {
    messages: VecDeque<Message>,
    /// Last issued, so the next is +1. Messages are not persisted, so this restarts at 0.
    last_seq: u64,
    tasks: Vec<Task>,
    /// Last issued task number; restored from the ids in `tasks.json` so an id is never
    /// reused across a restart.
    last_task: u64,
    /// Where every task change is written before it is acknowledged. `None` = memory only,
    /// which is what this module's own tests and the server's stub boards want.
    path: Option<PathBuf>,
    /// Why `tasks.json` would not load. While set, every task verb refuses with it rather than
    /// start from an empty board, whose first save would overwrite the user's file.
    broken: Option<String>,
}

impl Board {
    // ---- messages ----

    /// Returns the new message's `seq`.
    pub(crate) fn post(&mut self, from: &str, text: &str, to: Option<&str>) -> Result<u64, String> {
        let text = validate_text("text", text, MAX_MESSAGE_CHARS)?;
        let to = to.map(|t| validate_text("to", t, MAX_NAME_CHARS)).transpose()?;
        self.last_seq += 1;
        self.messages.push_back(Message { seq: self.last_seq, from: from.to_string(), to, text });
        while self.messages.len() > MESSAGE_RING {
            self.messages.pop_front();
        }
        Ok(self.last_seq)
    }

    /// Everything after `after_seq`, oldest first, at most `limit`, plus the EXACT number of
    /// messages the ring dropped before this cursor reached them.
    pub(crate) fn read(&self, after_seq: u64, limit: usize) -> (Vec<&Message>, u64) {
        // Nothing retained: the cursor has missed nothing it could still have been given.
        let oldest = self.messages.front().map_or(self.last_seq + 1, |m| m.seq);
        let missed = oldest.saturating_sub(after_seq + 1);
        (self.messages.iter().filter(|m| m.seq > after_seq).take(limit).collect(), missed)
    }

    /// The newest seq issued — a fresh reader's cursor, and what `unread` counts down from.
    pub(crate) fn last_seq(&self) -> u64 {
        self.last_seq
    }

    // ---- tasks ----

    pub(crate) fn tasks(&self) -> &[Task] {
        &self.tasks
    }

    fn active(&self) -> usize {
        self.tasks.iter().filter(|t| !t.state.is_terminal()).count()
    }

    /// The task board is readable, or here is why not.
    pub(crate) fn check(&self) -> Result<(), String> {
        self.broken.as_ref().map_or(Ok(()), |e| Err(e.clone()))
    }

    /// THE way a task changes: the change is on disk before the caller can acknowledge it, and
    /// a failed write puts the board back — an agent told "no" must not find the task claimed
    /// in its name on its next read. Every pub(crate) task verb below is a call to this.
    fn commit<T>(&mut self, change: impl FnOnce(&mut Board) -> Result<T, String>) -> Result<T, String> {
        self.check()?;
        let before = (self.tasks.clone(), self.last_task);
        let out = change(self)?;
        if let Some(path) = &self.path {
            if let Err(e) = self.save_to(path) {
                (self.tasks, self.last_task) = before;
                return Err(format!("the task board could not be saved, so nothing changed: {e}"));
            }
        }
        Ok(out)
    }

    pub(crate) fn create_task(
        &mut self,
        creator: &str,
        title: &str,
        detail: Option<&str>,
        assignee: Option<&str>,
    ) -> Result<Task, String> {
        self.commit(|b| b.create(creator, title, detail, assignee))
    }

    pub(crate) fn claim_task(&mut self, actor: &str, id: &str) -> Result<Task, String> {
        self.commit(|b| b.claim(actor, id))
    }

    pub(crate) fn update_task(
        &mut self,
        actor: &str,
        id: &str,
        state: TaskState,
        note: Option<&str>,
    ) -> Result<Task, String> {
        self.commit(|b| b.update(actor, id, state, note))
    }

    /// Spend one of a task's `MAX_TASK_PROPOSALS`. Only the holder of a claimed task may; for
    /// anyone else, and for an id that does not exist, the answer is the exhausted budget's,
    /// word for word — `task_id` must not be a way to learn whose task is whose (R20).
    pub(crate) fn charge_proposal(&mut self, actor: &str, id: &str) -> Result<(), String> {
        self.commit(|b| {
            let spent = || {
                format!("task {id} has no proposals left for you \u{2014} a task gets {MAX_TASK_PROPOSALS}, and only while you hold it")
            };
            let task = b
                .tasks
                .iter_mut()
                .find(|t| t.id == id && t.state == TaskState::Claimed && t.holder.as_deref() == Some(actor))
                .ok_or_else(spent)?;
            if task.proposals >= MAX_TASK_PROPOSALS {
                return Err(spent());
            }
            task.proposals += 1;
            Ok(())
        })
    }

    fn create(
        &mut self,
        creator: &str,
        title: &str,
        detail: Option<&str>,
        assignee: Option<&str>,
    ) -> Result<Task, String> {
        let title = validate_task_text("title", title, MAX_TITLE_CHARS)?;
        let detail = detail.map(|d| validate_task_text("detail", d, MAX_DETAIL_CHARS)).transpose()?;
        let assignee = assignee.map(|a| validate_text("assignee", a, MAX_NAME_CHARS)).transpose()?;
        if self.active() >= MAX_ACTIVE_TASKS {
            return Err(format!(
                "the task board already has {MAX_ACTIVE_TASKS} active tasks \u{2014} finish or cancel one first"
            ));
        }
        // Full board: the OLDEST FINISHED task makes room. Unfinished work is never evicted,
        // so a flood of new tasks cannot push somebody's claimed task off the board.
        while self.tasks.len() >= MAX_TASKS {
            let Some(i) = self.tasks.iter().position(|t| t.state.is_terminal()) else {
                return Err("the task board is full and every task on it is unfinished".into());
            };
            self.tasks.remove(i);
        }
        self.last_task += 1;
        let task = Task {
            id: format!("t_{}", self.last_task),
            title,
            detail,
            creator: creator.to_string(),
            assignee,
            state: TaskState::Open,
            holder: None,
            claims: 0,
            note: None,
            proposals: 0,
        };
        self.tasks.push(task.clone());
        Ok(task)
    }

    fn claim(&mut self, actor: &str, id: &str) -> Result<Task, String> {
        let task = self.tasks.iter_mut().find(|t| t.id == id).ok_or(NO_SUCH_TASK)?;
        // Not an oracle: claiming is something any agent may do to any open task, so the
        // state it is actually in is the honest answer and is what ends a race.
        if task.state != TaskState::Open {
            return Err(format!(
                "task {id} is {} \u{2014} only an open task can be claimed",
                task.state.as_str()
            ));
        }
        // The manager's tasks are its plan, and it reads a holder's `failed` or `done` as the
        // assignee's: a stranger's claim could fail a task out of the plan, spend its
        // reassignments or queue its check. `manager` is a reserved name, so no token creates
        // as it. Not an oracle either: the assignee is on every task listing.
        if task.creator == "manager" && task.assignee.as_deref() != Some(actor) {
            return Err(format!("task {id} is the manager's, for its assignee only \u{2014} only they can claim it"));
        }
        if task.claims >= MAX_CLAIMS {
            return Err(format!(
                "task {id} has been claimed {MAX_CLAIMS} times already \u{2014} it is not being handed out again"
            ));
        }
        task.claims += 1;
        task.state = TaskState::Claimed;
        task.holder = Some(actor.to_string());
        Ok(task.clone())
    }

    /// `done` and `failed` are the holder's to set; `cancelled` is the holder's or the
    /// creator's. Every other caller is answered exactly like an unknown id.
    fn update(&mut self, actor: &str, id: &str, state: TaskState, note: Option<&str>) -> Result<Task, String> {
        // Before the lookup, so a malformed note answers the same whoever's task it names.
        let note = note.map(|n| validate_task_text("note", n, MAX_DETAIL_CHARS)).transpose()?;
        if !state.is_terminal() {
            return Err("a task can only be moved to done, failed or cancelled".into());
        }
        let task = self.tasks.iter_mut().find(|t| t.id == id).ok_or(NO_SUCH_TASK)?;
        let allowed = match state {
            TaskState::Cancelled => {
                task.holder.as_deref() == Some(actor) || task.creator == actor
            }
            _ => task.holder.as_deref() == Some(actor),
        };
        if !allowed {
            return Err(NO_SUCH_TASK.into());
        }
        if task.state.is_terminal() {
            return Err(format!("task {id} is already {}", task.state.as_str()));
        }
        task.state = state;
        if note.is_some() {
            task.note = note;
        }
        // `holder` is left as the record of who finished it.
        Ok(task.clone())
    }

    // ---- tasks.json (v1, frozen) ----

    /// Nobody holds a task across a restart: the process that claimed it is gone, so the work
    /// is nobody's again. `claims` is deliberately untouched — see `Task::claims`.
    fn reopen_claimed(&mut self) {
        for task in self.tasks.iter_mut().filter(|t| t.state == TaskState::Claimed) {
            task.state = TaskState::Open;
            task.holder = None;
        }
    }

    /// The live board. Infallible on purpose: a `tasks.json` that will not load leaves the
    /// board `broken` — the task verbs refuse with the reason until the user fixes the file —
    /// while the message board, which never touches disk, carries on.
    pub(crate) fn load() -> Board {
        match tasks_path() {
            Ok(path) => Board::open(path),
            Err(e) => Board { broken: Some(e), ..Board::default() },
        }
    }

    /// Load `path` and write every later task change back to it.
    pub(crate) fn open(path: PathBuf) -> Board {
        match Board::load_from(&path) {
            Ok(board) => Board { path: Some(path), ..board },
            Err(e) => Board { broken: Some(e), ..Board::default() },
        }
    }

    fn load_from(path: &Path) -> Result<Board, String> {
        let Some(file) = crate::read_config::<TasksFile>(path)? else {
            return Ok(Board::default()); // no file yet: an empty board, not an error
        };
        if file.version != TASKS_VERSION {
            return Err(format!(
                "{} is version {} \u{2014} this build writes version {TASKS_VERSION}; fix or delete it",
                path.display(),
                file.version
            ));
        }
        let mut board = Board { tasks: file.tasks, ..Board::default() };
        board.reopen_claimed();
        // Ids are never reused, so the counter resumes above the highest one on disk.
        board.last_task = board
            .tasks
            .iter()
            .filter_map(|t| t.id.strip_prefix("t_").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0);
        Ok(board)
    }

    fn save_to(&self, path: &Path) -> Result<(), String> {
        crate::write_config(path, &TasksFile { version: TASKS_VERSION, tasks: self.tasks.clone() })
    }
}

const TASKS_VERSION: u32 = 1;

/// `{ "version": 1, "tasks": [...] }`. `version` has no serde default on purpose: a file
/// without one is not a v1 file, and guessing is how a format stops being frozen.
#[derive(serde::Serialize, serde::Deserialize)]
struct TasksFile {
    version: u32,
    tasks: Vec<Task>,
}

pub(crate) fn tasks_path() -> Result<PathBuf, String> {
    Ok(crate::config_dir()?.join("tasks.json"))
}

// ---- the turn lock ----
//
// One shell, one holder, everyone else in a FIFO queue. A pure state machine over an injected
// clock: no guard, no handle, no mutex and no clock read of its own. The server owns all
// four — it passes `now` in and turns the `Event`s every operation returns into taking and
// dropping the approval slot's guard — so the lock never has to know a guard exists, and
// every rule below is asserted at its exact boundary instead of waited out.

pub(crate) use turn::*;

mod turn {
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    /// An `Idle` holder silent this long has gone away: the turn goes to the next waiter.
    pub(crate) const LEASE_IDLE: Duration = Duration::from_secs(60);
    /// The most `Idle` time one turn may use, however often its holder checks in: keeping a lease
    /// alive is not the same as using the shell while others wait.
    pub(crate) const MAX_TURN: Duration = Duration::from_secs(10 * 60);
    /// A waiter that has not polled for this long has gone away, and gives up its place.
    pub(crate) const WAITER_SILENCE: Duration = Duration::from_secs(90);
    /// Waiters, not counting the holder. A request past this is refused rather than queued.
    pub(crate) const QUEUE_MAX: usize = 8;

    /// Monotonic and never reused, so a stale ticket can never name a later turn.
    pub(crate) type Ticket = u64;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum HolderState {
        /// Holds the shell with nothing in flight. The only state in which the clocks run.
        Idle,
        /// A proposal is on the bar. Frozen: the human may take as long as they like, because
        /// there is no approval timeout, ever.
        AwaitingHuman,
        /// Approved and written; its Block has not arrived.
        Running,
        /// Written, and the wait for its Block ran out: a foreground command may still own the
        /// shell. Frozen, and never handed on by the lock — only a deliberate release ends it (R21).
        Unknown,
    }

    pub(crate) struct Turn {
        pub(crate) ticket: Ticket,
        pub(crate) agent: String,
        pub(crate) state: HolderState,
        /// When `state` was entered.
        pub(crate) since: Instant,
        /// Asked for with `request_turn`: a command ending hands it back `Idle` instead of
        /// releasing it. Recorded here, at the request, because the grant may land between the
        /// caller's polls — the reply that finds it cannot say how it was asked for.
        pub(crate) kept: bool,
        /// The holder's last call: the lease measures silence from here.
        last_seen: Instant,
        /// `Idle` time used by this turn's earlier `Idle` stretches: `MAX_TURN`'s clock, which
        /// only runs while `Idle`.
        idle_spent: Duration,
    }

    impl Turn {
        /// `Idle` time this turn has used, the current stretch included. Meaningful only in `Idle`.
        fn idle_used(&self, now: Instant) -> Duration {
            self.idle_spent + now.saturating_duration_since(self.since)
        }

        /// How long until the turn is taken back; `None` = never by the clock, which is every state
        /// but `Idle`. The one place the lease and `MAX_TURN` are computed, for the sweep and for
        /// whoever shows the countdown.
        pub(crate) fn expires_in(&self, now: Instant) -> Option<Duration> {
            (self.state == HolderState::Idle).then(|| {
                let lease = LEASE_IDLE.saturating_sub(now.saturating_duration_since(self.last_seen));
                lease.min(MAX_TURN.saturating_sub(self.idle_used(now)))
            })
        }
    }

    pub(crate) struct Waiter {
        pub(crate) ticket: Ticket,
        pub(crate) agent: String,
        last_seen: Instant,
        kept: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum Request {
        Granted(Ticket),
        /// `position` is 1-based: 1 is next.
        Queued { ticket: Ticket, position: usize },
        QueueFull,
        AlreadyHolder(Ticket),
        /// ⌘J took this agent's `Idle` turn since it last asked. Said once, and nothing queued:
        /// a caller mid-sequence must learn another command may have run between its own.
        Preempted,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Revoke {
        Released,
        Lease,
        MaxTurn,
        Preempted,
    }

    /// What an operation did to who holds the shell — the server's cue to take or drop the guard.
    /// In the order it happened: a revoke comes before the grant it made room for.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum Event {
        Granted { ticket: Ticket, agent: String },
        Revoked { ticket: Ticket, agent: String, reason: Revoke },
        Pruned { agent: String },
    }

    #[derive(Default)]
    pub(crate) struct TurnLock {
        holder: Option<Turn>,
        queue: VecDeque<Waiter>,
        last_ticket: Ticket,
        /// Agents ⌘J preempted that have not asked since. At most one entry per name: a
        /// preempted agent holds nothing until its next request, which clears it.
        preempted: Vec<String>,
    }

    impl TurnLock {
        pub(crate) fn holder(&self) -> Option<&Turn> {
            self.holder.as_ref()
        }

        pub(crate) fn waiters(&self) -> impl Iterator<Item = &Waiter> {
            self.queue.iter()
        }

        /// Idempotent: the holder, or an agent already queued, gets its own ticket back and counts
        /// as having checked in. A new agent is queued and, if the shell is free, granted at once.
        /// `keep` = asked with `request_turn`; a later plain request never un-asks it.
        pub(crate) fn request(&mut self, agent: &str, now: Instant, keep: bool) -> (Request, Vec<Event>) {
            let mut events = self.sweep(now);
            if let Some(i) = self.preempted.iter().position(|a| a == agent) {
                self.preempted.swap_remove(i);
                return (Request::Preempted, events);
            }
            if let Some(t) = self.holder.as_mut().filter(|t| t.agent == agent) {
                t.last_seen = now;
                t.kept |= keep;
                return (Request::AlreadyHolder(t.ticket), events);
            }
            if let Some(i) = self.queue.iter().position(|w| w.agent == agent) {
                self.queue[i].last_seen = now;
                self.queue[i].kept |= keep;
                return (Request::Queued { ticket: self.queue[i].ticket, position: i + 1 }, events);
            }
            if self.queue.len() >= QUEUE_MAX {
                return (Request::QueueFull, events);
            }
            self.last_ticket += 1;
            let ticket = self.last_ticket;
            self.queue.push_back(Waiter { ticket, agent: agent.to_string(), last_seen: now, kept: keep });
            // Through the queue even when the shell is free, so a grant has exactly one road.
            self.grant_head(now, &mut events);
            let reply = if self.holder.as_ref().is_some_and(|t| t.ticket == ticket) {
                Request::Granted(ticket)
            } else {
                Request::Queued { ticket, position: self.queue.len() }
            };
            (reply, events)
        }

        /// The holder gives the turn up and the head is granted; a waiter gives up its place. A
        /// `Running` holder is refused: its command owns the shell's foreground, and handing that
        /// on is exactly what the lock exists to prevent. `Unknown` is allowed — it is the one way
        /// out of it, and a deliberate one.
        pub(crate) fn release(&mut self, agent: &str, now: Instant) -> Vec<Event> {
            let mut events = self.sweep(now);
            match &self.holder {
                Some(t) if t.agent == agent => {
                    if t.state != HolderState::Running {
                        self.revoke(Revoke::Released, &mut events);
                        self.grant_head(now, &mut events);
                    }
                }
                _ => self.queue.retain(|w| w.agent != agent),
            }
            events
        }

        /// Keyed by TICKET, not by name: a late report from a turn that already ended (a Block
        /// finally arriving after the human released an `Unknown`) must not move the same agent's
        /// next turn — marking a live command `Idle` would let the lease hand it on.
        pub(crate) fn set_state(&mut self, ticket: Ticket, state: HolderState, now: Instant) -> Vec<Event> {
            // A ticket that is not the holder's is a turn already over — a command's late
            // settle, a Block for a released turn. It is not a lock op: it must not sweep, or
            // a worker that finished long ago would be the one granting the head of the queue.
            if self.holder.as_ref().is_none_or(|t| t.ticket != ticket) {
                return Vec::new();
            }
            let events = self.sweep(now);
            if let Some(t) = self.holder.as_mut().filter(|t| t.ticket == ticket) {
                if t.state == HolderState::Idle {
                    t.idle_spent = t.idle_used(now);
                }
                t.state = state;
                t.since = now;
                t.last_seen = now;
            }
            events
        }

        /// The caller is alive: resets the holder's lease or the waiter's silence.
        pub(crate) fn touch(&mut self, agent: &str, now: Instant) -> Vec<Event> {
            // A caller with no turn and no place in line has nothing to keep alive, so its
            // message is not a lock op: it must not sweep, or any agent reading the board would
            // be the one granting the head of the queue. Waiters re-ask every retry_after_ms
            // and every hub_state read sweeps, so a lapsed lease is still noticed in time.
            let mine = self.holder.as_ref().is_some_and(|t| t.agent == agent) || self.queue.iter().any(|w| w.agent == agent);
            if !mine {
                return Vec::new();
            }
            let events = self.sweep(now);
            if let Some(t) = self.holder.as_mut().filter(|t| t.agent == agent) {
                t.last_seen = now;
            } else if let Some(w) = self.queue.iter_mut().find(|w| w.agent == agent) {
                w.last_seen = now;
            }
            events
        }

        /// ⌘J takes the shell back from an IDLE holder only; in any other state it fails fast as
        /// it always has. No sweep and no grant: the shell is being freed for the built-in agent,
        /// and granting the head here would hand it straight to someone else.
        pub(crate) fn preempt_if_idle(&mut self, _now: Instant) -> Vec<Event> {
            let mut events = Vec::new();
            if let Some(t) = self.holder.as_ref().filter(|t| t.state == HolderState::Idle) {
                self.preempted.push(t.agent.clone());
                self.revoke(Revoke::Preempted, &mut events);
            }
            events
        }

        /// A grant the server could not honour — ⌘J holds the approval slot, which the lock
        /// cannot see — goes back to the HEAD of the queue: that waiter is still next. Dropping
        /// it instead would empty the queue on every lock op while ⌘J runs, and hand the shell
        /// to whoever polls first afterwards. No event: a turn that never got its guard has none
        /// to drop.
        pub(crate) fn requeue_holder(&mut self, ticket: Ticket) {
            if let Some(t) = self.holder.take_if(|t| t.ticket == ticket) {
                self.queue.push_front(Waiter { ticket, agent: t.agent, last_seen: t.last_seen, kept: t.kept });
            }
        }

        /// Every clock rule, in order: an expired `Idle` holder loses the turn, silent waiters are
        /// pruned (so a dead one is never granted), then a free shell goes to the head. A holder in
        /// any other state is untouched here, `Unknown` above all.
        pub(crate) fn sweep(&mut self, now: Instant) -> Vec<Event> {
            let mut events = Vec::new();
            if let Some(t) = &self.holder {
                if t.expires_in(now) == Some(Duration::ZERO) {
                    let reason = if t.idle_used(now) >= MAX_TURN { Revoke::MaxTurn } else { Revoke::Lease };
                    self.revoke(reason, &mut events);
                }
            }
            self.queue.retain(|w| {
                let alive = now.saturating_duration_since(w.last_seen) < WAITER_SILENCE;
                if !alive {
                    events.push(Event::Pruned { agent: w.agent.clone() });
                }
                alive
            });
            self.grant_head(now, &mut events);
            events
        }

        fn revoke(&mut self, reason: Revoke, events: &mut Vec<Event>) {
            if let Some(t) = self.holder.take() {
                events.push(Event::Revoked { ticket: t.ticket, agent: t.agent, reason });
            }
        }

        fn grant_head(&mut self, now: Instant, events: &mut Vec<Event>) {
            if self.holder.is_some() {
                return;
            }
            if let Some(w) = self.queue.pop_front() {
                events.push(Event::Granted { ticket: w.ticket, agent: w.agent.clone() });
                self.holder = Some(Turn {
                    ticket: w.ticket,
                    agent: w.agent,
                    state: HolderState::Idle,
                    since: now,
                    kept: w.kept,
                    last_seen: now,
                    idle_spent: Duration::ZERO,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board_with(messages: u64) -> Board {
        let mut b = Board::default();
        for i in 1..=messages {
            b.post("codex", &format!("m{i}"), None).unwrap();
        }
        b
    }

    /// Per-test directory: cargo runs these in parallel threads of one process.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tachyon-tasks-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn message_ids_and_seqs_are_monotonic() {
        let b = board_with(3);
        let (msgs, missed) = b.read(0, 100);
        assert_eq!(missed, 0);
        assert_eq!(msgs.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(msgs[0].id(), "m_1");
        assert_eq!(b.last_seq(), 3);
    }

    #[test]
    fn the_ring_holds_500_and_reports_the_exact_miss() {
        let b = board_with(600);
        assert_eq!(b.messages.len(), MESSAGE_RING);
        let (msgs, missed) = b.read(0, 100);
        // 1..=100 were evicted, so a cursor at 0 is told exactly that before it reads 101.
        assert_eq!(missed, 100);
        assert_eq!(msgs[0].seq, 101);
        // a cursor inside the ring has missed nothing, and the window is gapless
        let (msgs, missed) = b.read(500, 100);
        assert_eq!(missed, 0);
        assert_eq!(msgs.iter().map(|m| m.seq).collect::<Vec<_>>(), (501..=600).collect::<Vec<_>>());
        // and a cursor at the head reads nothing rather than repeating the last message
        assert_eq!(b.read(600, 100).0.len(), 0);
        assert_eq!(board_with(0).read(0, 100).1, 0);
    }

    #[test]
    fn the_author_is_whoever_the_caller_says_it_is_and_nothing_else() {
        let mut b = Board::default();
        // There is no `from` argument: the only name that can land here is the one the
        // server read off the bearer token.
        b.post("codex", "hi", Some("claude")).unwrap();
        assert_eq!(b.read(0, 1).0[0].from, "codex");
        assert_eq!(b.read(0, 1).0[0].to.as_deref(), Some("claude"));
    }

    /// R3, on the board's side: the corpus that `run_command` refuses is refused here too.
    /// MUTATION: dropping the `is_control() || is_invisible` line in `validate_text` turns
    /// this red on the first three cases; dropping the length check kills the last two.
    #[test]
    fn every_text_field_refuses_control_bidi_and_overlong() {
        let mut b = Board::default();
        for bad in ["two\nlines", "tab\there", "bidi\u{202E}flip", "zero\u{200B}width", "", "   "] {
            assert!(b.post("codex", bad, None).is_err(), "post accepted {bad:?}");
            assert!(b.create_task("codex", bad, None, None).is_err(), "create accepted {bad:?}");
        }
        assert!(b.post("codex", &"x".repeat(MAX_MESSAGE_CHARS + 1), None).is_err());
        assert!(b.post("codex", &"x".repeat(MAX_MESSAGE_CHARS), None).is_ok());
        assert!(b.create_task("codex", &"x".repeat(MAX_TITLE_CHARS + 1), None, None).is_err());
        let long = "x".repeat(MAX_DETAIL_CHARS + 1);
        assert!(b.create_task("codex", "title", Some(&long), None).is_err());
        // and every string on the way in, not just the obvious one
        assert!(b.post("codex", "hi", Some("cla\u{202E}ude")).is_err());
        assert!(b.create_task("codex", "title", None, Some("x".repeat(33).as_str())).is_err());
    }

    #[test]
    fn a_task_runs_open_then_claimed_then_terminal() {
        let mut b = Board::default();
        let t = b.create_task("claude", "implement the parser", Some("in src/x.rs"), Some("codex")).unwrap();
        assert_eq!(t.id, "t_1");
        assert_eq!(t.state, TaskState::Open);
        assert_eq!(t.assignee.as_deref(), Some("codex"));

        let t = b.claim_task("codex", "t_1").unwrap();
        assert_eq!((t.state, t.holder.as_deref(), t.claims), (TaskState::Claimed, Some("codex"), 1));
        // claiming is not an assignment: the creator's suggestion survives untouched
        assert_eq!(t.assignee.as_deref(), Some("codex"));

        assert!(b.claim_task("claude", "t_1").is_err(), "a claimed task was claimed twice");
        let t = b.update_task("codex", "t_1", TaskState::Done, Some("done")).unwrap();
        assert_eq!((t.state, t.note.as_deref()), (TaskState::Done, Some("done")));
        assert!(b.claim_task("codex", "t_1").is_err(), "a finished task was claimed");
        assert!(b.update_task("codex", "t_1", TaskState::Failed, None).is_err());
        assert_eq!(b.create_task("claude", "next", None, None).unwrap().id, "t_2");
    }

    #[test]
    fn only_a_terminal_state_can_be_set() {
        let mut b = Board::default();
        b.create_task("claude", "t", None, None).unwrap();
        b.claim_task("codex", "t_1").unwrap();
        for s in [TaskState::Open, TaskState::Claimed] {
            assert!(b.update_task("codex", "t_1", s, None).is_err(), "{} was settable", s.as_str());
        }
    }

    /// R20. MUTATION: replacing the `if !allowed` body with `Ok(task.clone())` turns the
    /// first two asserts red; returning a distinct string there turns the third red.
    #[test]
    fn a_foreign_task_answers_exactly_like_an_unknown_one() {
        let mut b = Board::default();
        b.create_task("claude", "mine", None, None).unwrap();
        b.claim_task("codex", "t_1").unwrap();

        let foreign = b.update_task("mallory", "t_1", TaskState::Done, None).unwrap_err();
        let unknown = b.update_task("mallory", "t_999", TaskState::Done, None).unwrap_err();
        assert_eq!(foreign, unknown, "ownership is leaking through the error");
        assert_eq!(foreign, NO_SUCH_TASK);
        assert_eq!(b.tasks()[0].state, TaskState::Claimed, "a foreign update went through");

        // cancel: the holder and the creator, nobody else
        assert!(b.update_task("mallory", "t_1", TaskState::Cancelled, None).is_err());
        assert!(b.update_task("claude", "t_1", TaskState::Cancelled, None).is_ok());
        let mut b = Board::default();
        b.create_task("claude", "mine", None, None).unwrap();
        b.claim_task("codex", "t_1").unwrap();
        assert!(b.update_task("codex", "t_1", TaskState::Cancelled, None).is_ok());
    }

    /// MUTATION: dropping the `claims >= MAX_CLAIMS` guard in `claim_task` makes the fourth
    /// claim succeed and this go red.
    #[test]
    fn the_fourth_claim_of_a_task_is_refused() {
        let mut b = Board::default();
        b.create_task("claude", "cursed", None, None).unwrap();
        for i in 1..=MAX_CLAIMS {
            assert_eq!(b.claim_task("codex", "t_1").unwrap().claims, i);
            b.reopen_claimed(); // as a restart would, after the holder died
        }
        assert!(b.claim_task("codex", "t_1").is_err(), "claim {} went through", MAX_CLAIMS + 1);
    }

    /// A stranger cannot take up the manager's task, so it cannot fail it out of the plan,
    /// burn its reassignments or report it done to queue its check; an agent's task is still
    /// anyone's to claim. MUTATION: dropping the `creator == "manager"` guard in `claim` lets
    /// mallory claim t_1 and turns the first assert red.
    #[test]
    fn only_the_assignee_claims_a_task_of_the_managers() {
        let mut b = Board::default();
        b.create_task("manager", "planned", None, Some("codex")).unwrap();
        assert!(b.claim_task("mallory", "t_1").unwrap_err().contains("only they can claim it"));
        assert_eq!((b.tasks()[0].state, b.tasks()[0].claims), (TaskState::Open, 0), "a refused claim changed the task");
        assert!(b.claim_task("codex", "t_1").is_ok());
        b.create_task("claude", "anyone's", None, Some("codex")).unwrap();
        assert!(b.claim_task("mallory", "t_2").is_ok());
    }

    #[test]
    fn tasks_are_capped_and_the_oldest_finished_one_is_evicted() {
        let mut b = Board::default();
        for i in 0..MAX_ACTIVE_TASKS {
            b.create_task("claude", &format!("t{i}"), None, None).unwrap();
        }
        assert!(b.create_task("claude", "one too many", None, None).is_err());

        // finish them all, then keep going: total is capped by evicting the oldest finished
        for i in 1..=MAX_ACTIVE_TASKS {
            let id = format!("t_{i}");
            b.claim_task("codex", &id).unwrap();
            b.update_task("codex", &id, TaskState::Done, None).unwrap();
        }
        while b.tasks().len() < MAX_TASKS {
            let n = b.tasks().len();
            let id = b.create_task("claude", &format!("f{n}"), None, None).unwrap().id;
            b.claim_task("codex", &id).unwrap();
            b.update_task("codex", &id, TaskState::Done, None).unwrap();
        }
        b.create_task("claude", "overflow", None, None).unwrap();
        assert_eq!(b.tasks().len(), MAX_TASKS);
        assert_eq!(b.tasks()[0].id, "t_2", "eviction did not take the oldest");
        assert_eq!(b.tasks().last().unwrap().title, "overflow");
    }

    #[test]
    fn an_active_task_is_never_evicted() {
        let mut b = Board::default();
        b.create_task("claude", "active", None, None).unwrap();
        while b.tasks().len() < MAX_TASKS {
            let n = b.tasks().len();
            let id = b.create_task("claude", &format!("f{n}"), None, None).unwrap().id;
            b.claim_task("codex", &id).unwrap();
            b.update_task("codex", &id, TaskState::Done, None).unwrap();
        }
        b.create_task("claude", "overflow", None, None).unwrap();
        assert_eq!(b.tasks()[0].title, "active");
    }

    #[test]
    fn tasks_json_round_trips_and_a_restart_reopens_without_burning_a_claim() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("tasks.json");

        assert_eq!(Board::load_from(&path).unwrap().tasks().len(), 0); // missing = empty

        let mut b = Board::default();
        b.create_task("claude", "implement the parser", Some("src/x.rs"), Some("codex")).unwrap();
        b.create_task("claude", "second", None, None).unwrap();
        b.claim_task("codex", "t_1").unwrap();
        b.update_task("claude", "t_2", TaskState::Cancelled, Some("never mind")).unwrap();
        b.save_to(&path).unwrap();

        let loaded = Board::load_from(&path).unwrap();
        let t = &loaded.tasks()[0];
        assert_eq!((t.state, t.holder.as_deref()), (TaskState::Open, None), "the holder survived a restart");
        assert_eq!(t.claims, 1, "a crashed holder burned a claim");
        assert_eq!((t.title.as_str(), t.detail.as_deref(), t.assignee.as_deref()), ("implement the parser", Some("src/x.rs"), Some("codex")));
        assert_eq!(loaded.tasks()[1].state, TaskState::Cancelled, "a finished task was reopened");
        assert_eq!(loaded.tasks()[1].note.as_deref(), Some("never mind"));

        // ids resume above what is on disk rather than colliding with it
        let mut loaded = loaded;
        assert_eq!(loaded.create_task("claude", "third", None, None).unwrap().id, "t_3");

        // the shape on disk is the frozen one
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], 1);
        assert_eq!(raw["tasks"][0]["id"], "t_1");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R15. MUTATION: making `load_from` fall back to `Board::default()` on a parse error
    /// turns the `is_err` asserts red; a `save_to` anywhere on that path turns the byte
    /// comparison red.
    #[test]
    fn a_corrupt_or_unversioned_tasks_json_is_an_error_and_is_left_alone() {
        let dir = temp_dir("corrupt");
        let path = dir.join("tasks.json");
        for bad in [
            "{not json",
            r#"{"version":1,"tasks":"nope"}"#,
            r#"{"tasks":[]}"#,                  // no version at all
            r#"{"version":2,"tasks":[]}"#,      // a version this build does not write
            r#"{"version":"1","tasks":[]}"#,
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(Board::load_from(&path).is_err(), "{bad} loaded");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad, "{bad} was overwritten");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// MUTATION: dropping the `holder == actor` term in `charge_proposal` turns the first
    /// assert red; dropping the `>= MAX_TASK_PROPOSALS` guard turns the 21st red.
    #[test]
    fn a_task_budget_is_the_holders_alone_and_stops_at_twenty() {
        let mut b = Board::default();
        b.create_task("claude", "t", None, None).unwrap();
        let unclaimed = b.charge_proposal("claude", "t_1").unwrap_err();
        b.claim_task("codex", "t_1").unwrap();
        let foreign = b.charge_proposal("mallory", "t_1").unwrap_err();
        for _ in 0..MAX_TASK_PROPOSALS {
            b.charge_proposal("codex", "t_1").unwrap();
        }
        let spent = b.charge_proposal("codex", "t_1").unwrap_err();
        assert_eq!(foreign, spent, "the budget refusal is an ownership oracle");
        assert_eq!(unclaimed, spent);
        assert_eq!(b.tasks()[0].proposals, MAX_TASK_PROPOSALS);
    }

    /// MUTATION: dropping the restore line in `commit` leaves t_1 on the board after the
    /// failed save and turns the `len() == 0` assert red.
    #[test]
    fn a_task_change_that_cannot_be_saved_does_not_happen() {
        let dir = temp_dir("unsaveable");
        let path = dir.join("tasks.json");
        let mut b = Board::open(path.clone());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "a file where the directory was").unwrap();
        assert!(b.create_task("claude", "lost", None, None).is_err(), "an unsaved task was acknowledged");
        assert_eq!(b.tasks().len(), 0);
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(b.create_task("claude", "kept", None, None).unwrap().id, "t_1", "the id counter leaked");
        assert!(std::fs::read_to_string(&path).unwrap().contains("kept"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R15 for the live board: a file that will not load is never replaced by an empty board.
    /// MUTATION: making `open` fall back to `Board { path: Some(path), ..default }` on error
    /// lets `create_task` through and over the file, and turns this red.
    #[test]
    fn a_broken_tasks_json_stops_the_task_verbs_and_nothing_else() {
        let dir = temp_dir("broken");
        let path = dir.join("tasks.json");
        std::fs::write(&path, "{not json").unwrap();
        let mut b = Board::open(path.clone());
        assert!(b.check().is_err());
        assert!(b.create_task("claude", "t", None, None).is_err());
        assert!(b.claim_task("claude", "t_1").is_err());
        assert!(b.post("claude", "the message board still works", None).is_ok());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json", "the user's file was overwritten");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C12b. Eight agents hammer one board for five seconds with a fixed seed, and every bound
    /// the module promises is checked after every operation, under the same lock that made
    /// it. Then the process "dies" and `tasks.json` is reloaded: nobody holds anything.
    /// MUTATIONS (each turns this red): dropping `claim`'s `!= Open` guard (a second claimer
    /// of one task); dropping `post`'s ring trim (ring > 500); dropping `create`'s active cap
    /// (> 64 active); dropping `create`'s eviction loop (> 256 total); dropping the
    /// `reopen_claimed()` call in `load_from` (a claimed task survives the reload).
    #[test]
    fn eight_agents_for_five_seconds_break_no_bound() {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        struct Shared {
            board: Board,
            /// Who won each claim. In one process a task goes Open -> Claimed exactly once.
            claimer: HashMap<String, String>,
            peak: (usize, usize, usize), // ring, active, total
        }

        fn check_bounds(s: &mut Shared) {
            let b = &s.board;
            assert!(b.messages.len() <= MESSAGE_RING, "ring at {}", b.messages.len());
            assert!(b.messages.iter().zip(b.messages.iter().skip(1)).all(|(x, y)| y.seq == x.seq + 1));
            assert!(b.messages.back().is_none_or(|m| m.seq == b.last_seq));
            assert!(b.active() <= MAX_ACTIVE_TASKS, "{} active", b.active());
            assert!(b.tasks.len() <= MAX_TASKS, "{} tasks", b.tasks.len());
            for t in &b.tasks {
                match t.state {
                    TaskState::Open => assert_eq!(t.holder, None, "{} is open with a holder", t.id),
                    TaskState::Claimed => {
                        assert_eq!(t.holder.as_ref(), s.claimer.get(&t.id), "{} has two holders", t.id)
                    }
                    _ => {}
                }
            }
            let p = &mut s.peak;
            *p = (p.0.max(b.messages.len()), p.1.max(b.active()), p.2.max(b.tasks.len()));
        }

        let dir = temp_dir("stress");
        let path = dir.join("tasks.json");
        // In memory while the threads run: a board that writes tasks.json on every change is
        // paced by the disk, and CI's could not reach the ring's 500 in 5 s. The bounds are
        // the board's, not the disk's; the file is written once, below, and reloaded.
        let shared = Arc::new(Mutex::new(Shared {
            board: Board::default(),
            claimer: HashMap::new(),
            peak: (0, 0, 0),
        }));
        let start = Instant::now();
        let workers: Vec<_> = (0..8u64)
            .map(|n| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let me = format!("a{n}");
                    // Knuth's MMIX LCG: deterministic per thread, no crate.
                    let mut x = 0x7AC4_1011u64 ^ n;
                    let mut next = move || {
                        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        x >> 33
                    };
                    let mut held: Vec<String> = Vec::new();
                    while start.elapsed() < Duration::from_secs(5) {
                        let r = next();
                        let mut s = shared.lock().unwrap();
                        // A recent id, so claims and cancels land on live tasks.
                        let recent = format!("t_{}", s.board.last_task.saturating_sub(r % 80).max(1));
                        match r % 10 {
                            0..=2 => {
                                let _ = s.board.create_task(&me, &format!("w{r}"), None, None);
                            }
                            3..=5 => {
                                if let Ok(t) = s.board.claim_task(&me, &recent) {
                                    assert_eq!(t.holder.as_deref(), Some(me.as_str()));
                                    let prev = s.claimer.insert(t.id.clone(), me.clone());
                                    assert_eq!(prev, None, "{} was claimed twice", t.id);
                                    held.push(t.id);
                                }
                            }
                            6..=7 => {
                                let state = [TaskState::Done, TaskState::Failed, TaskState::Cancelled][(r % 3) as usize];
                                // Mostly finish own work; sometimes try someone else's, which
                                // only a creator's cancel may do.
                                let id = if r % 4 != 0 { held.pop().unwrap_or(recent) } else { recent };
                                let _ = s.board.update_task(&me, &id, state, Some("n"));
                            }
                            _ => {
                                let before = s.board.last_seq();
                                let seq = s.board.post(&me, &format!("m{r}"), None).unwrap();
                                assert_eq!(seq, before + 1, "seq is not strictly monotonic");
                            }
                        }
                        check_bounds(&mut s);
                    }
                })
            })
            .collect();
        for w in workers {
            assert!(w.join().is_ok(), "a worker panicked");
        }
        assert!(start.elapsed() < Duration::from_secs(10), "stress took {:?}", start.elapsed());

        let mut s = Arc::try_unwrap(shared).ok().unwrap().into_inner().unwrap();
        // Non-vacuous: the run reached every ceiling it claims to hold.
        assert_eq!(s.peak, (MESSAGE_RING, MAX_ACTIVE_TASKS, MAX_TASKS), "the run never reached the bounds");
        s.board.path = Some(path.clone());
        s.board.save_to(&path).unwrap();
        if !s.board.tasks.iter().any(|t| t.state == TaskState::Claimed) {
            let id = s.board.tasks.iter().find(|t| t.state == TaskState::Open).expect("no open task").id.clone();
            s.board.claim_task("a0", &id).unwrap();
        }
        let before: Vec<(String, u32)> = s.board.tasks.iter().map(|t| (t.id.clone(), t.claims)).collect();
        drop(s);

        let reloaded = Board::open(path);
        reloaded.check().unwrap();
        let after: Vec<(String, u32)> = reloaded.tasks.iter().map(|t| (t.id.clone(), t.claims)).collect();
        assert_eq!(after, before, "tasks.json is not the board that was dropped");
        assert!(reloaded.tasks.iter().all(|t| t.state != TaskState::Claimed && (t.state != TaskState::Open || t.holder.is_none())));
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- the turn lock ----

    use std::time::{Duration, Instant};

    fn secs(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    fn granted(ticket: Ticket, agent: &str) -> Event {
        Event::Granted { ticket, agent: agent.into() }
    }

    fn revoked(ticket: Ticket, agent: &str, reason: Revoke) -> Event {
        Event::Revoked { ticket, agent: agent.into(), reason }
    }

    fn holder_of(l: &TurnLock) -> Option<(Ticket, &str, HolderState)> {
        l.holder().map(|t| (t.ticket, t.agent.as_str(), t.state))
    }

    /// MUTATION: returning a fresh ticket from the holder or waiter branch of `request` turns
    /// the `AlreadyHolder(1)` / second `Queued` asserts red.
    #[test]
    fn a_free_shell_is_granted_and_a_rerequest_is_idempotent() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        assert_eq!(l.request("a", t0, false), (Request::Granted(1), vec![granted(1, "a")]));
        assert_eq!(l.request("a", t0, false), (Request::AlreadyHolder(1), vec![]));
        assert_eq!(l.request("b", t0, false), (Request::Queued { ticket: 2, position: 1 }, vec![]));
        assert_eq!(l.request("b", t0, false), (Request::Queued { ticket: 2, position: 1 }, vec![]));
        assert_eq!(l.waiters().count(), 1, "a re-request queued the agent twice");
    }

    /// MUTATION: dropping the `>= QUEUE_MAX` guard queues the ninth; `push_front` for
    /// `push_back` breaks the grant order.
    #[test]
    fn the_queue_is_fifo_across_eight_and_refuses_the_ninth() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("h", t0, false);
        for i in 0..QUEUE_MAX {
            let (reply, _) = l.request(&format!("w{i}"), t0, false);
            assert_eq!(reply, Request::Queued { ticket: i as u64 + 2, position: i + 1 });
        }
        assert_eq!(l.request("late", t0, false).0, Request::QueueFull);
        assert_eq!(l.release("h", t0), vec![revoked(1, "h", Revoke::Released), granted(2, "w0")]);
        for i in 1..QUEUE_MAX {
            let prev = format!("w{}", i - 1);
            let events = l.release(&prev, t0);
            assert_eq!(events[1], granted(i as u64 + 2, &format!("w{i}")), "grant out of order");
        }
        // The refused request took no ticket, and tickets are never reused: 1..=9 are spent.
        assert_eq!(l.request("late", t0, false).0, Request::Queued { ticket: 10, position: 1 });
        l.release("w7", t0);
        assert_eq!(l.request("h", t0, false).0, Request::Queued { ticket: 11, position: 1 }, "a ticket was reused");
    }

    /// MUTATION: making `sweep` revoke at `expires_in <= 1 s` revokes at 59 s and turns the
    /// boundary assert red; dropping the holder's `last_seen = now` in `touch` turns the
    /// "touch did not reset the lease" assert red.
    #[test]
    fn the_lease_revokes_an_idle_holder_at_sixty_seconds_of_silence_and_grants_the_head() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.request("b", t0, false);
        assert_eq!(l.sweep(t0 + LEASE_IDLE - Duration::from_millis(1)), vec![]);
        assert_eq!(l.sweep(t0 + LEASE_IDLE), vec![revoked(1, "a", Revoke::Lease), granted(2, "b")]);
        let b = l.holder().unwrap();
        assert_eq!((b.state, b.since), (HolderState::Idle, t0 + LEASE_IDLE));

        // Any call from the holder is what keeps the lease.
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.touch("a", secs(t0, 50));
        assert_eq!(l.holder().unwrap().expires_in(secs(t0, 100)), Some(Duration::from_secs(10)));
        assert_eq!(l.sweep(secs(t0, 109)), vec![], "touch did not reset the lease");
        assert_eq!(l.sweep(secs(t0, 110)), vec![revoked(1, "a", Revoke::Lease)]);
        assert!(l.holder().is_none());
    }

    /// MUTATION: dropping the `.min(MAX_TURN …)` term in `expires_in` keeps the turn alive for
    /// ever and turns this red.
    #[test]
    fn max_turn_revokes_from_idle_despite_activity() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        for s in (30..MAX_TURN.as_secs()).step_by(30) {
            assert_eq!(l.touch("a", secs(t0, s)), vec![], "revoked at {s}s");
        }
        assert_eq!(l.holder().unwrap().expires_in(secs(t0, 599)), Some(Duration::from_secs(1)));
        assert_eq!(l.touch("a", t0 + MAX_TURN), vec![revoked(1, "a", Revoke::MaxTurn)]);
    }

    /// No approval timeout, and no command timeout: outside `Idle` both clocks stand still, and
    /// `MAX_TURN` counts only the `Idle` time. MUTATION: making `expires_in` run in every state
    /// turns the 11-minute asserts red; dropping the `idle_spent` carry in `set_state` (resetting
    /// MAX_TURN on each return to `Idle`) turns the last assert red.
    #[test]
    fn the_clocks_are_frozen_while_awaiting_running_or_unknown() {
        let t0 = Instant::now();
        for state in [HolderState::AwaitingHuman, HolderState::Running, HolderState::Unknown] {
            let mut l = TurnLock::default();
            l.request("a", t0, false);
            assert_eq!(l.set_state(1, state, t0), vec![]);
            let later = t0 + Duration::from_secs(11 * 60);
            assert_eq!(l.sweep(later), vec![], "{state:?} was revoked by the clock");
            assert_eq!(l.holder().unwrap().expires_in(later), None);
            // Back to Idle: a fresh lease, and none of the frozen time charged to MAX_TURN.
            l.set_state(1, HolderState::Idle, later);
            assert_eq!(l.holder().unwrap().expires_in(later), Some(LEASE_IDLE), "{state:?}");
        }

        // 9 min Idle, a long Running, then Idle again: one minute of MAX_TURN is left.
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        for s in (30..=540).step_by(30) {
            l.touch("a", secs(t0, s));
        }
        l.set_state(1, HolderState::Running, secs(t0, 540));
        l.set_state(1, HolderState::Idle, secs(t0, 3600));
        l.touch("a", secs(t0, 3630));
        assert_eq!(l.sweep(secs(t0, 3659)), vec![]);
        assert_eq!(l.sweep(secs(t0, 3660)), vec![revoked(1, "a", Revoke::MaxTurn)]);
    }

    /// R21. MUTATION: letting `sweep` revoke any holder whose clock would have run out (i.e.
    /// computing the lease in `Unknown`) turns the hour-long assert red.
    #[test]
    fn a_holder_in_unknown_is_never_handed_on_by_the_lock() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.request("b", t0, false);
        l.set_state(1, HolderState::Unknown, t0);
        // b keeps polling, so only the rule under test could move the turn.
        for s in (60..=3600).step_by(60) {
            assert_eq!(l.touch("b", secs(t0, s)), vec![], "moved at {s}s");
        }
        assert_eq!(holder_of(&l), Some((1, "a", HolderState::Unknown)));
        assert_eq!(l.preempt_if_idle(secs(t0, 3600)), vec![], "⌘J took an Unknown shell");
        // The deliberate way out.
        assert_eq!(
            l.release("a", secs(t0, 3600)),
            vec![revoked(1, "a", Revoke::Released), granted(2, "b")]
        );
    }

    /// MUTATION: making every waiter `alive` in `sweep` leaves b queued and hands it the turn.
    #[test]
    fn a_silent_waiter_is_pruned_at_ninety_seconds_and_never_granted() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.request("b", t0, false);
        l.request("c", t0, false);
        l.set_state(1, HolderState::Running, t0);
        l.touch("c", secs(t0, 60));
        assert_eq!(l.sweep(t0 + WAITER_SILENCE - Duration::from_millis(1)), vec![]);
        assert_eq!(l.sweep(t0 + WAITER_SILENCE), vec![Event::Pruned { agent: "b".into() }]);
        assert_eq!(l.request("c", secs(t0, 100), false).0, Request::Queued { ticket: 3, position: 1 });
        l.set_state(1, HolderState::Idle, secs(t0, 100));
        assert_eq!(l.release("a", secs(t0, 100)), vec![revoked(1, "a", Revoke::Released), granted(3, "c")]);

        // A dead waiter at the head when the lease runs out: pruned first, never granted.
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.request("b", t0, false);
        l.set_state(1, HolderState::Running, t0);
        l.set_state(1, HolderState::Idle, secs(t0, 60));
        assert_eq!(
            l.sweep(secs(t0, 120)),
            vec![revoked(1, "a", Revoke::Lease), Event::Pruned { agent: "b".into() }]
        );
        assert!(l.holder().is_none());
    }

    /// ⌘J outranks an IDLE holder only, and frees the shell for itself rather than for the
    /// queue. MUTATION: dropping the `== Idle` filter in `preempt_if_idle` turns the loop red;
    /// adding a `grant_head` there turns the `holder().is_none()` assert red.
    #[test]
    fn preempt_acts_only_from_idle_and_grants_nobody() {
        let t0 = Instant::now();
        for state in [HolderState::AwaitingHuman, HolderState::Running, HolderState::Unknown] {
            let mut l = TurnLock::default();
            l.request("a", t0, false);
            l.set_state(1, state, t0);
            assert_eq!(l.preempt_if_idle(t0), vec![], "{state:?} was preempted");
            assert_eq!(holder_of(&l), Some((1, "a", state)));
        }
        let mut l = TurnLock::default();
        assert_eq!(l.preempt_if_idle(t0), vec![]);
        l.request("a", t0, false);
        l.request("b", t0, false);
        assert_eq!(l.preempt_if_idle(t0), vec![revoked(1, "a", Revoke::Preempted)]);
        assert!(l.holder().is_none(), "preempt handed the shell to the queue");
        assert_eq!(l.waiters().next().unwrap().agent, "b", "the waiter lost its place");
    }

    /// ⌘J holds the approval slot, so the server hands every grant straight back: the waiter
    /// keeps its place at the head, and the order survives however many ops run meanwhile.
    /// MUTATION: `push_back` for `push_front` in `requeue_holder` grants b first.
    #[test]
    fn a_grant_handed_back_keeps_its_place_at_the_head() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        assert_eq!(l.request("a", t0, false).1, vec![granted(1, "a")]);
        l.requeue_holder(1);
        assert_eq!(l.request("b", t0, false).1, vec![granted(1, "a")], "a lost the head");
        l.requeue_holder(1);
        assert!(l.holder().is_none());
        assert_eq!(l.waiters().map(|w| w.agent.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        l.requeue_holder(7); // not the holder's ticket: nothing moves
        assert_eq!(l.sweep(t0), vec![granted(1, "a")], "the slot freed: the head, in order");
    }

    /// Kept is how the turn was ASKED for, not how the reply that found it reads. MUTATION:
    /// dropping `kept |= keep` for a queued agent turns the first assert red; granting with
    /// `kept: true` (or `false`) turns one of the other two red.
    #[test]
    fn kept_is_recorded_at_the_request() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.request("b", t0, false);
        l.request("b", t0, true); // queued, then asked with request_turn
        l.request("c", t0, false);
        l.release("a", t0);
        assert!(l.holder().unwrap().kept, "request_turn while queued was forgotten");
        l.release("b", t0);
        assert!(!l.holder().unwrap().kept, "a run_command grant came back kept");
        l.request("c", t0, true);
        assert!(l.holder().unwrap().kept, "the holder asking to keep was ignored");
    }

    /// ⌘J's preempt is told to the agent it hit, once, on its next request — and only a real
    /// preempt counts. MUTATION: dropping the `preempted.push` turns the first assert red;
    /// dropping the `swap_remove` answers `Preempted` for ever.
    #[test]
    fn a_preempted_agent_is_told_once() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, true);
        l.preempt_if_idle(t0);
        assert_eq!(l.request("a", t0, true), (Request::Preempted, vec![]));
        assert!(l.holder().is_none() && l.waiters().next().is_none(), "a refusal queued the agent");
        assert_eq!(l.request("a", t0, true).0, Request::Granted(2));
        l.release("a", t0);
        assert_eq!(l.request("a", t0, false).0, Request::Granted(3), "a release read as a preempt");
    }

    /// R20 at the lock: a release by anyone but the holder moves nothing. And R21: a
    /// `Running` holder cannot let go. MUTATION: dropping the `!= Running` check in `release`
    /// turns the Running assert red; matching on anything but the holder's name there turns
    /// the stranger assert red.
    #[test]
    fn only_the_holder_releases_and_never_while_running() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.request("b", t0, false);
        l.request("c", t0, false);
        assert_eq!(l.release("mallory", t0), vec![]);
        assert_eq!(l.release("c", t0), vec![], "a waiter's release moved the turn");
        assert_eq!(holder_of(&l), Some((1, "a", HolderState::Idle)));
        assert_eq!(l.waiters().map(|w| w.agent.as_str()).collect::<Vec<_>>(), ["b"], "c kept its place");

        l.set_state(1, HolderState::Running, t0);
        assert_eq!(l.release("a", t0), vec![], "a Running shell was handed on");
        assert_eq!(holder_of(&l), Some((1, "a", HolderState::Running)));
        l.set_state(1, HolderState::AwaitingHuman, t0);
        assert_eq!(l.release("a", t0), vec![revoked(1, "a", Revoke::Released), granted(2, "b")]);
    }

    /// A late report from an ended turn must not move the same agent's next one. MUTATION:
    /// matching `set_state` on the agent's name instead of the ticket turns this red.
    #[test]
    fn set_state_is_keyed_by_ticket() {
        let t0 = Instant::now();
        let mut l = TurnLock::default();
        l.request("a", t0, false);
        l.set_state(1, HolderState::Unknown, t0);
        l.release("a", t0);
        assert_eq!(l.request("a", t0, false).0, Request::Granted(2));
        l.set_state(2, HolderState::Running, t0);
        // ticket 1's command finally prints its Block
        l.set_state(1, HolderState::Idle, secs(t0, 5));
        assert_eq!(holder_of(&l), Some((2, "a", HolderState::Running)));
        // ...and a stale ticket is not a lock op: with the shell free and "b" queued, it
        // grants nobody and changes nothing, however late the clock it carries.
        l.set_state(2, HolderState::Idle, secs(t0, 6));
        l.release("a", secs(t0, 6));
        assert_eq!(l.request("c", secs(t0, 7), false).0, Request::Granted(3)); // the shell is free
        l.requeue_holder(3); // parked at the head, the way ⌘J's failed claim leaves it
        assert_eq!(holder_of(&l), None);
        assert!(l.set_state(1, HolderState::Idle, secs(t0, 1000)).is_empty(), "a stale settle swept the lock");
        assert_eq!(holder_of(&l), None, "a stale settle granted the head");
        // Nor is a stranger's message: an agent that never asked for the shell grants nobody.
        assert!(l.touch("stranger", secs(t0, 1000)).is_empty(), "a stranger's touch swept the lock");
        assert_eq!(holder_of(&l), None, "a stranger's touch granted the head");
        assert_eq!(l.waiters().map(|w| w.agent.as_str()).collect::<Vec<_>>(), ["c"]);
    }

    /// The module map's rule, enforced rather than remembered: this file stays free of the
    /// app handle, of Tauri types and of the runtime, so the board can be reasoned about (and
    /// tested) without either. The turn lock adds two: no clock of its own (so every lease rule
    /// is tested at its boundary) and no mutex (R12 — the server's lock is statement-scoped,
    /// and a second one in here is a lock order waiting to invert).
    #[test]
    fn coord_stays_a_plain_module() {
        let live = include_str!("coord.rs").split("#[cfg(test)]").next().unwrap();
        for needle in ["AppHandle", "tauri::", "async fn", ".await", "\nstatic ", "Instant::now", "lock("] {
            assert!(!live.contains(needle), "coord.rs contains {needle}");
        }
        assert!(live.contains("fn post") && live.contains("fn sweep"), "the scan went vacuous");
    }
}
