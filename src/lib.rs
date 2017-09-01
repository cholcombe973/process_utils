//! Just some random process manipulation functions that I've found useful

extern crate nix;
#[macro_use]
extern crate log;
extern crate procinfo;

use std::fs;
use std::io::{Error, ErrorKind, Read};
use std::io::Result as IOResult;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use procinfo::pid::{stat, Stat};

/// Walk through /proc and find all processes with the name that
/// equals the cmd_name.
pub fn find_all_pids(cmd_name: &str) -> IOResult<Vec<Stat>> {
    let mut info: Vec<Stat> = Vec::new();
    for entry in fs::read_dir("/proc/")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let file_name = match path.file_name() {
                Some(f) => f,
                None => {
                    //Unable to determine file name
                    debug!("Unable to determine file name for {:?}. Skipping", path);
                    continue;
                }
            };
            debug!("Parsing pid: {:?}", file_name);
            let pid = match i32::from_str(&file_name.to_string_lossy()) {
                Ok(p) => p,
                Err(_) => {
                    trace!("Skipping entry: {:?}.  Not a process", file_name);
                    continue;
                }
            };
            let s = stat(pid)?;
            if s.command == cmd_name {
                info.push(s);
            }
        } else {
            // Skip entries for anything not a process
            trace!("Skipping entry: {:?}.  Not a process", path);
            continue;
        }
    }
    Ok(info)
}

/// Get the cmdline used to start the process
pub fn get_cmdline(pid: i32) -> IOResult<Vec<String>> {
    let mut f = fs::File::open(format!("/proc/{}/cmdline", pid))?;
    let mut buff = String::new();
    f.read_to_string(&mut buff)?;
    let args: Vec<String> = buff.split("\0")
        .map(String::from)
        .filter(|arg| !arg.is_empty())
        .collect();
    for arg in &args {
        trace!("cmd arg: {:?}", arg.as_bytes());
    }
    Ok(args)
}

/// Simple spinlock that waits a certain number of milliseconds while
/// a pid still exists.
pub fn spinlock(pid: i32) {
    while Path::new(&format!("/proc/{}", pid)).exists() {
        trace!("Sleeping 10ms");
    }
}

/// Kills a process and optionally the parent process and restarts them.
/// simulate will just log and not kill anything. Currently
/// SIGTERM is used to nicely stop processes and wait for them to exit.
/// If you need a bigger hammer this isn't the function for you.
//TODO This function is too long
pub fn kill_and_restart(
    pid_info: Vec<Stat>,
    limit: u64,
    kill_parent: bool,
    simulate: bool,
) -> IOResult<()> {
    for stat_info in pid_info {
        if stat_info.vsize > limit as usize {
            let cmdline = if kill_parent {
                get_cmdline(stat_info.ppid)?
            } else {
                get_cmdline(stat_info.pid)?
            };
            debug!("cmdline: {:?}", cmdline);
            println!(
                "Killing {} process {} for memory at {} and restarting.  Cmdline: {}",
                cmdline[0],
                stat_info.pid,
                stat_info.vsize,
                cmdline.join(" ")
            );
            // If this isn't a simulation we're actually going to kill/restart things here
            if !simulate {
                // Safety first!
                if stat_info.pid == 1 {
                    warn!("Cannot kill pid 1.  Please verify what you're doing here");
                    continue;
                }
                kill(Pid::from_raw(stat_info.pid), Signal::SIGTERM)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                // Spinlock wait for the process to stop
                spinlock(stat_info.pid);
                if kill_parent {
                    if stat_info.ppid == 1 {
                        warn!("Cannot kill pid 1.  Please verify what you're doing here");
                        continue;
                    }
                    println!("Also killing parent process: {}", stat_info.ppid);
                    kill(Pid::from_raw(stat_info.ppid), Signal::SIGTERM)
                        .map_err(|e| Error::new(ErrorKind::Other, e))?;
                    // Spinlock wait for the process to stop
                    spinlock(stat_info.ppid);
                }
                println!("Starting {} up again", cmdline[0]);
                // Restart the process
                Command::new(&cmdline[0]).args(&cmdline[1..]).spawn()?;
                println!("Process successfully spawned");
            }
        }
    }
    Ok(())
}
