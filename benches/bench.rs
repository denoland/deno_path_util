use std::borrow::Cow;
use std::path::PathBuf;

use deno_path_util::normalize_path;

fn main() {
  // Run registered benchmarks.
  divan::main();
}

#[divan::bench]
fn bench_normalize_path_changed(bencher: divan::Bencher) {
  let path = PathBuf::from("/testing/../this/./out/testing/../test");
  bencher.bench(|| normalize_path(Cow::Borrowed(&path)))
}

#[divan::bench]
fn bench_normalize_path_no_change(bencher: divan::Bencher) {
  let path = PathBuf::from("/testing/this/out/testing/test");
  bencher.bench(|| normalize_path(Cow::Borrowed(&path)))
}
