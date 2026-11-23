//! bimo-agent — the single BIMO PC agent binary.
//!
//! One process, one thread, blocking on the event bus. No polling,
//! no timers, no background threads at rest. The secure link, the
//! event feed, the guard and the island all plug into the same bus.

use bimo_core::{run, Bus, Event};
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Windows proof gate: --gate [--gate-out path]
    // Runs the draw experiment on a real Windows host and exits with
    // the gate verdict (0 pass / 1 fail / 2 could not run).
    if args.iter().any(|a| a == "--gate") {
        let out = args
            .windows(2)
            .find(|w| w[0] == "--gate-out")
            .map(|w| w[1].as_str());
        std::process::exit(bimo_island::run_gate(out));
    }

    let bus = Bus::new();
    let tx = bus.tx.clone();

    // Demo producer (dev only): feeds one synthetic event sequence so
    // the state machine can be exercised end-to-end on Linux, then
    // the agent settles into pure idle. In production the producers
    // are the Windows event hooks + the secure link, not this thread.
    let demo = std::env::args().any(|a| a == "--demo");
    if demo {
        std::thread::spawn(move || {
            let seq = [
                Event::AgentWork { started: true, summary: "demo install".into() },
                Event::AgentSpeaking { speaking: true },
                Event::AgentSpeaking { speaking: false },
            ];
            for ev in seq {
                std::thread::sleep(std::time::Duration::from_millis(300));
                if tx.send(ev).is_err() {
                    return;
                }
            }
            // Then silence: the agent must sit idle forever.
        });
    }

    let log = std::env::args().any(|a| a == "--log");
    run(bus.rx, |state, ev| {
        bimo_island::present(state, ev);
        if log {
            let _ = writeln!(
                std::io::stderr(),
                "[{}] {:?} -> {:?}",
                bimo_core::now_iso(),
                ev,
                state
            );
        }
    });
}
