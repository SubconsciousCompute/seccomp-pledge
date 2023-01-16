use assert_cmd::prelude::*;
use std::process::Command;
use predicates::prelude::*;

// Integration tests

#[test]
pub fn with_no_restrictions() {
    let mut cmd = Command::cargo_bin("seccomp-pledge").expect("Binary not found");
    // Escapes quotes, so promises are supplied separately
    cmd.args(
        ["-no-check", "--local", "--no-api", "-v", ".", "-p", "stdio", "-p", "rpath", "-p", "tty", "ls"])
        .assert()
        .stdout(predicate::str::contains("LICENSE"));
}

#[test]
pub fn with_unveil_restrictions() {
    let mut cmd = Command::cargo_bin("seccomp-pledge").expect("Binary not found");
    // Escapes quotes, so promises are supplied separately
    cmd.args(
        ["-no-check", "--local", "--no-api", "-p", "stdio", "-p", "rpath", "-p", "tty", "ls"])
        .assert()
        .stderr(predicate::str::contains("Insufficient path permissions"));
}


#[test]
pub fn with_pledge_restrictions() {
    let mut cmd = Command::cargo_bin("seccomp-pledge").expect("Binary not found");
    // Escapes quotes, so promises are supplied separately
    cmd.args(
        ["-no-check", "--local", "--no-api", "-v", ".", "ls"])
        .assert()
        .stderr(predicate::str::contains("Insufficient syscall permissions"));
}
