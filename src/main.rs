#![deny(warnings)]

use caps::{CapSet, Capability};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, exit};
use std::str::FromStr;

use libc::{PR_SET_NO_NEW_PRIVS, PR_SET_SECUREBITS, c_ulong};
const SECBIT_NOROOT: c_ulong = 0x01;
const DEFAULT_CONFIG_PATH: Option<&'static str> = option_env!("DEFAULT_CONFIG_PATH");

macro_rules! fail {
    ($($arg:tt)*) => ({
        let msg = format!("ERROR: {}\n", format_args!($($arg)*));
        let _ = std::io::stderr().write_all(msg.as_bytes());
        exit(1)
    })
}

#[derive(Deserialize)]
struct Config {
    helpers: Vec<Helper>,
}

impl Config {
    // Modernization & Refactoring: Encapsulated configuration loading and parsing.
    fn load(path: &str) -> Self {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|e| fail!("couldn't read config file {}: {}", path, e));

        toml::from_str(&raw)
            .unwrap_or_else(|e| fail!("couldn't parse config file {}: {}", path, e))
    }

    fn find_helper(&self, args: &[OsString]) -> &Helper {
        // Note: The kernel guarantees argv[0] exists for usermode helpers.
        // We panic/fail if it's missing.
        let name = args.get(0).expect("program doesn't have a 0 arg?");
        self.helpers
            .iter()
            .find(|s| s.allowed(args))
            .unwrap_or_else(|| fail!("invalid usermode helper {:?}", name))
    }
}

#[derive(Deserialize)]
struct Helper {
    path: String,
    argc: Option<usize>,
    #[serde(deserialize_with = "deserialize_caps", default)]
    // Modernization: Use 'caps' crate (Hashet) instead of the old 'capabilities'.
    capabilities: Option<HashSet<Capability>>,
}

impl Helper {
    fn allowed(&self, args: &[OsString]) -> bool {
        if !args.get(0).map_or(false, |a| a == self.path.as_str()) {
            return false;
        }
        if let Some(argc) = self.argc {
            if args.len() != argc {
                return false;
            }
        }
        true
    }

    fn execute(&self, args: &[OsString]) {
        // Modernization: Use std::process::Command instead of unsafe libc::execvp.
        // We set up a minimal environment for the new process.
        let mut cmd = Command::new(&self.path);

        cmd.env_clear()
            .env("HOME", "/")
            .env("TERM", "linux")
            .env("PATH", "/sbin:/bin:/usr/sbin:/usr/bin")
            .args(args.iter().skip(1))
            .arg0(&self.path);

        let err = cmd.exec();
        fail!("exec failed: {}", err);
    }
}

// Modernization: Migrating to the modern 'caps' crate logic.
// The legacy libcap string format (e.g., "= cap_sys_module+eip") is still supported,
// but flags are ignored to enforce a strict allowlist.
fn deserialize_caps<'de, D>(deserializer: D) -> Result<Option<HashSet<Capability>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let clean_s = s.trim().trim_start_matches("=").trim();

    if clean_s.is_empty() {
        return Ok(None);
    }

    let caps = clean_s
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let name = part.split(|c| c == '+' || c == '-').next().unwrap_or(part);
            Capability::from_str(&name.to_uppercase())
                .map_err(|_| serde::de::Error::custom(format!("bad caps {}", name)))
        })
        .collect::<Result<HashSet<_>, _>>()?;

    Ok(Some(caps))
}

// Security Hardening: Enforce a deterministic FD state to prevent any
// attacker-controlled descriptors from leaking into the target command.
fn sanitize_fds() {
    let nfd = match fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
        Ok(f) => f.into_raw_fd(),
        Err(_) => exit(2),
    };
    let fail_if = |failed: bool| {
        if failed {
            exit(3);
        }
    };

    unsafe {
        // Sanitize standards streams (0, 1 2) -> /dev/null
        fail_if(libc::dup2(nfd, libc::STDIN_FILENO) < 0);
        fail_if(libc::dup2(nfd, libc::STDOUT_FILENO) < 0);
        fail_if(libc::dup2(nfd, libc::STDERR_FILENO) < 0);

        // Close all others (3+).
        fail_if(libc::syscall(libc::SYS_close_range, 3, !0u32, 0) < 0);
    }
}

// Logic change: Simplified to "best effort".
// Removed 'eprintln' (since stderr is not yet connected) and 'CString' allocations.
fn log_to_kmsg() {
    if let Ok(f) = fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        unsafe {
            libc::dup2(f.as_raw_fd(), libc::STDERR_FILENO);
        }
    }
}

// Refactoring: Isolate privilege restriction (caps, NNP) into a dedidcated function.
fn priv_restrict(caps_to_apply: &HashSet<Capability>) {
    // 1. Disable "Magic Root" behavior.
    // Instruct kernel NOT to automatically grant full capabilities during execve.
    unsafe {
        if libc::prctl(PR_SET_SECUREBITS, SECBIT_NOROOT, 0, 0, 0) < 0 {
            fail!("couln't set securebits");
        }
    }

    // 2. Drop all capabilities from Effective, Inheritable and Permitted sets,
    // except the ones explicitly allowed in configuration.
    for set in [CapSet::Effective, CapSet::Inheritable, CapSet::Permitted] {
        caps::set(None, set, caps_to_apply)
            .unwrap_or_else(|e| fail!("couldn't apply caps to {:?}: {}", set, e));
    }

    // 3. Add allowed capabilities to the Ambient set so they persist across execve.
    for cap in caps_to_apply {
        caps::raise(None, CapSet::Ambient, *cap)
            .unwrap_or_else(|e| fail!("couldn't set ambient cap {:?}: {}", cap, e));
    }

    // 4. Security Hardening: Set the NNP (No New Privileges) bit.
    // NNP complements SECBIT_NOROOT by ensuring privileges cannot be re-acquired
    // after execve (e.g., through setuid/setgid bit or file capabilities).
    unsafe {
        if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            fail!("failed to set nnp");
        }
    }
}

fn main() {
    sanitize_fds();
    log_to_kmsg();

    let path = DEFAULT_CONFIG_PATH.unwrap_or("/etc/usermode-helper.conf");
    let config = Config::load(path);

    let args: Vec<OsString> = std::env::args_os().collect();
    let helper = config.find_helper(&args);

    // Restrict privileges based on configured capabilities.
    if let Some(caps) = &helper.capabilities {
        priv_restrict(caps);
    }

    /* ALTERNATIVE APPROACH ("Zero-Trust"):
     * If no capabilties are defined (empty set), strip all privileges.
     *
     *  let empty_caps = HashSet::new();
     *  let caps = helper.capabilities.as_ref().unwrap_or(&empty_caps);
     *  priv_restrict(caps);
     */

    if std::env::var("HULDUFOLK_DEBUG").is_ok() {
        let msg = format!("-- DEBUG CAPS for {} --\n", helper.path);
        let _ = std::io::stderr().write_all(msg.as_bytes());
        for set in [
            CapSet::Effective,
            CapSet::Inheritable,
            CapSet::Permitted,
            CapSet::Ambient,
        ] {
            let c = caps::read(None, set).unwrap_or_default();
            let line = format!("{:?}: {:?}\n", set, c);
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }

    helper.execute(&args);
}
