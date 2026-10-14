//! The interop program for ports/conformance/interop.py (spec/PORTING.md, "The interop program"):
//!     interop URL AGENT_IDS SECONDS          (token in SMARTWATCH_INGEST_TOKEN)
//! One command poller per agent (200 ms) prints "RESET <agent_id> <reset_id>" for every command and
//! acknowledges it; SECONDS x 10 rounds of one message per ordered pair of agents every 100 ms go
//! through the reporter; then "SENT <messages accepted>"; it keeps polling until standard input closes.
use smartwatch::client::{Client, CommandPoller, Reporter};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: interop URL AGENT_IDS SECONDS");
        std::process::exit(2);
    }
    let url = &args[1];
    let ids: Vec<String> = args[2].split(',').map(str::to_string).collect();
    let seconds: u64 = args[3].parse().unwrap_or_else(|_| {
        eprintln!("SECONDS must be an integer");
        std::process::exit(2)
    });
    let token = std::env::var("SMARTWATCH_INGEST_TOKEN").ok();
    let client = Client::new(url, token.as_deref()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(2)
    });
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let pollers: Vec<CommandPoller> = ids
        .iter()
        .map(|a| {
            let (agent, out) = (a.clone(), Arc::clone(&out));
            let p = CommandPoller::new(
                client.clone(),
                a,
                Duration::from_millis(200),
                Box::new(move |cmd| {
                    let rid = cmd.get("reset_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let mut o = out.lock().unwrap_or_else(|e| e.into_inner());
                    writeln!(o, "RESET {} {}", agent, rid).and_then(|_| o.flush()).map_err(|e| e.to_string())
                }),
            );
            p.start();
            p
        })
        .collect();
    let rep = Reporter::new(url, token.as_deref()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(2)
    });
    rep.start();
    let t0 = Instant::now();
    for r in 0..seconds * 10 {
        for a in &ids {
            for b in &ids {
                if a != b {
                    if let Err(e) = rep.record(a, b, 1) {
                        eprintln!("{}", e);
                    }
                }
            }
        }
        let next = t0 + Duration::from_millis((r + 1) * 100);
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        }
    }
    rep.close();
    {
        let mut o = out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(o, "SENT {}", rep.sent());
        let _ = o.flush();
    }
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    for p in &pollers {
        p.stop();
    }
}
