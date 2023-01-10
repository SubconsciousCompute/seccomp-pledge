use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("add_bench", |b| {
        b.iter(|| {})
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
