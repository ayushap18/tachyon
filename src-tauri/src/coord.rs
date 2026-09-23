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
    /// Advisory, and settable ONLY by the creator at creation: a worker cannot hand its work
    /// to another agent. Claiming is not restricted to the assignee — the board suggests who
    /// should take a task, it does not bind anyone to it.
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
        let shared = Arc::new(Mutex::new(Shared {
            board: Board::open(path.clone()),
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

    /// The module map's rule, enforced rather than remembered: this file stays free of the
    /// app handle, of Tauri types and of the runtime, so the board can be reasoned about (and
    /// tested) without either.
    #[test]
    fn coord_stays_a_plain_module() {
        let live = include_str!("coord.rs").split("#[cfg(test)]").next().unwrap();
        for needle in ["AppHandle", "tauri::", "async fn", ".await", "\nstatic "] {
            assert!(!live.contains(needle), "coord.rs contains {needle}");
        }
        assert!(live.contains("fn post"), "the scan went vacuous");
    }
}
