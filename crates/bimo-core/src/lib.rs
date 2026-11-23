//! bimo-core — the event-driven heart of the BIMO PC agent.
//!
//! Design rule (plan v2, performance budget): the agent does NOTHING
//! while nothing happens. No polling loop, no timer tick. The single
//! thread blocks on `Receiver::recv()` and wakes only when an event
//! arrives. Idle CPU must be ~0% and idle RAM in the tens of MB.
//!
//! Zero external dependencies on purpose: std only.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::SystemTime;

/// Everything the agent can observe or be told. The island renders
/// from these; the secure link forwards them to BIMO.
#[derive(Debug, Clone)]
pub enum Event {
    /// An application was opened or closed.
    App { name: String, opened: bool },
    /// A file was downloaded or changed on disk.
    FileChanged { path: String },
    /// A new file was quarantined/scanned by the guard module.
    ScanResult { path: String, clean: bool },
    /// BIMO (remote) started / finished working on something.
    AgentWork { started: bool, summary: String },
    /// BIMO is speaking to Yassin (voice note / reply in flight).
    AgentSpeaking { speaking: bool },
    /// A toast/alert worth popping the island open.
    Alert { text: String },
    /// Graceful shutdown (Yassin can stop the agent any time).
    Shutdown,
}

/// The visible state of the Dynamic Island. One state at a time;
/// transitions are driven purely by `Event`s, never by a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IslandState {
    /// Small resting pill (avatar circle + "BIMO" pill, per Yassin's
    /// 2026-11-22 reference screenshot).
    Resting,
    /// BIMO is working — avatar animated, pill expands slightly.
    Working,
    /// BIMO is speaking — avatar talks, pill expands with waveform.
    Speaking,
    /// A job just finished — brief "done" morph, then back to Resting.
    Done,
    /// Something needs Yassin's eyes — island pops open with the alert.
    Alert,
}

impl IslandState {
    /// Pure transition function: event in, new state out.
    /// `Done` is transient: the island layer (not the core) collapses
    /// it back to `Resting` after its animation finishes.
    pub fn on_event(self, ev: &Event) -> Self {
        match ev {
            Event::AgentWork { started: true, .. } => IslandState::Working,
            Event::AgentWork { started: false, .. } => IslandState::Done,
            Event::AgentSpeaking { speaking: true } => IslandState::Speaking,
            Event::AgentSpeaking { speaking: false } => IslandState::Done,
            Event::Alert { .. } => IslandState::Alert,
            Event::ScanResult { clean: false, .. } => IslandState::Alert,
            Event::Shutdown => IslandState::Resting,
            _ => self,
        }
    }
}

/// The event bus: producers send, the agent loop blocks on `recv()`.
pub struct Bus {
    pub tx: Sender<Event>,
    pub rx: Receiver<Event>,
}

impl Bus {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Bus { tx, rx }
    }
}

/// The agent loop. Blocks forever on the next event; wakes, applies
/// the state transition, hands the new state to the island renderer,
/// then sleeps again. Returns on `Shutdown`.
pub fn run<F>(rx: Receiver<Event>, mut on_state: F)
where
    F: FnMut(IslandState, &Event),
{
    let mut state = IslandState::Resting;
    loop {
        // BLOCKING wait — this is the whole idle story: the OS parks
        // this thread; it consumes no CPU until an event arrives.
        let ev = match rx.recv() {
            Ok(ev) => ev,
            Err(_) => return, // all senders dropped
        };
        if matches!(ev, Event::Shutdown) {
            on_state(IslandState::Resting, &ev);
            return;
        }
        let next = state.on_event(&ev);
        if next != state {
            state = next;
        }
        on_state(state, &ev);
    }
}

/// One-line timestamp for the local event log.
pub fn now_iso() -> String {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => format!("{}", d.as_secs()),
        Err(_) => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_walk() {
        let mut s = IslandState::Resting;
        s = s.on_event(&Event::AgentWork { started: true, summary: "install".into() });
        assert_eq!(s, IslandState::Working);
        s = s.on_event(&Event::AgentSpeaking { speaking: true });
        assert_eq!(s, IslandState::Speaking);
        s = s.on_event(&Event::AgentSpeaking { speaking: false });
        assert_eq!(s, IslandState::Done);
        s = s.on_event(&Event::Alert { text: "virus?".into() });
        assert_eq!(s, IslandState::Alert);
        // A plain file change does not disturb the island.
        s = s.on_event(&Event::FileChanged { path: "x".into() });
        assert_eq!(s, IslandState::Alert);
    }
}
