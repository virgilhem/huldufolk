# Huldufólk (Hardened Fork)

This is a fork of [huldufolk](https://github.com/tych0/huldufolk), a Rust implementation of the Linux kernel's `CONFIG_STATIC_USERMODEHELPER` interface.

## Changes

This fork updates the codebase to Rust 2024 and enforces stricter security defaults:

* Capability Management: Migrated to the `caps` crate (v0.5) utilizing the Ambient Set for correct privilege inheritance.
* Execution Hardening: Enforces NNP, sanitizes file descriptors, and clears the process environment. 
* Static Compilation: Configured to build statically against MUSL.

## Configuration

Configuration is handled via `/etc/usermode-helper.conf`. Example:

```toml
[[helpers]]
path = "/sbin/modprobe"
capabilities = "cap_sys_module"
argc = 4

[[helpers]]
path = "/sbin/reboot"
capabilities = "cap_sys_boot"
argc = 1
```

Actual privilege restriction logic is permissive by default:
* If capabilities are configured, the helper applies them strictly (dropping all others).
* If no capabilities are defined, the process remains full root. This is the legacy behavior.
