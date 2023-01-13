use criterion::{black_box, criterion_group, criterion_main, Criterion};
use assert_cmd::prelude::*;
use std::process::Command;
use predicates::prelude::*;

// Benchmarking

#[inline]
pub fn with_no_restrictions() {
    let mut cmd = Command::cargo_bin("seccomp-pledge").expect("Binary not found");
    // Escapes quotes, so promises are supplied separately
    cmd.args(
        ["-no-check", "--local", "--no-api", "-v", ".", "-p", "stdio", "-p", "rpath", "-p", "tty", "ls"])
        .assert()
        .stdout(predicate::str::contains("LICENSE"));
}

#[inline]
pub fn with_unveil_restrictions() {
    let mut cmd = Command::cargo_bin("seccomp-pledge").expect("Binary not found");
    // Escapes quotes, so promises are supplied separately
    cmd.args(
        ["-no-check", "--local", "--no-api", "-p", "stdio", "-p", "rpath", "-p", "tty", "ls"])
        .assert()
        .stderr(predicate::str::contains("Insufficient path permissions"));
}

#[inline]
pub fn with_pledge_restrictions() {
    let mut cmd = Command::cargo_bin("seccomp-pledge").expect("Binary not found");
    // Escapes quotes, so promises are supplied separately
    cmd.args(
        ["-no-check", "--local", "--no-api", "-v", ".", "ls"])
        .assert()
        .stderr(predicate::str::contains("Insufficient syscall permissions"));
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("add_bench", |b| {
        b.iter(|| {
            black_box(with_no_restrictions())
        })
    });
    c.bench_function("add_bench", |b| {
        b.iter(|| {
            black_box(with_unveil_restrictions())
        })
    });
    c.bench_function("add_bench", |b| {
        b.iter(|| {
            black_box(with_pledge_restrictions())
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
