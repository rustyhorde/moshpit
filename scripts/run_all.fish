#!/usr/bin/env fish

set run_tests true
set run_coverage true
set run_fuzz true
set run_docs true
set run_install true
set run_musl true
set musl_unstable false
set run_clean false

for arg in $argv
    switch $arg
        case --help -h
            echo "Usage: run_all.fish [OPTIONS]"
            echo ""
            echo "Runs the full moshpit CI pipeline locally."
            echo ""
            echo "Options:"
            echo "  --no-test      Skip nextest and all coverage steps"
            echo "  --no-coverage  Skip coverage steps only (lcov + html reports)"
            echo "  --no-fuzz      Skip the cargo fuzz steps"
            echo "  --no-docs      Skip the documentation step"
            echo "  --no-install   Skip the cargo install step"
            echo "  --no-musl      Skip the MUSL Docker build step"
            echo "  --unstable     Pass --unstable to run_musl.fish (builds unstable instead of stable)"
            echo "  --clean        Run cargo clean after all steps complete"
            echo "  --help, -h     Show this help message"
            echo ""
            echo "Steps (in order):"
            echo "  1.  cargo fmt"
            echo "  2.  cargo fmt --all -- --check"
            echo "  3.  cargo matrix clippy --all-targets -- -D warnings"
            echo "  4.  cargo matrix build"
            echo "  5.  cargo nextest run ...              (skipped with --no-test)"
            echo "  6.  cargo test (libmoshpit-fuzz)       (skipped with --no-test)"
            echo "  7.  cargo doc -p libmoshpit            (skipped with --no-docs)"
            echo "  8.  cargo llvm-cov nextest ...         (skipped with --no-test or --no-coverage)"
            echo "  9.  cargo llvm-cov report --lcov ...   (skipped with --no-test or --no-coverage)"
            echo "  10. cargo llvm-cov report --html       (skipped with --no-test or --no-coverage)"
            echo "  11. cargo fuzz run (30s each target)   (skipped with --no-fuzz)"
            echo "  12. run_install.fish                   (skipped with --no-install)"
            echo "  13. run_musl.fish                      (skipped with --no-musl; --unstable passed through)"
            echo "  14. cargo clean                        (only with --clean)"
            exit 0
        case --no-test
            set run_tests false
            set run_coverage false
        case --no-coverage
            set run_coverage false
        case --no-fuzz
            set run_fuzz false
        case --no-docs
            set run_docs false
        case --no-install
            set run_install false
        case --no-musl
            set run_musl false
        case --unstable
            set musl_unstable true
        case --clean
            set run_clean true
        case '*'
            echo "Unknown argument: $arg"
            echo "Run 'run_all.fish --help' for usage."
            exit 1
    end
end

function run_step
    echo ""
    echo "==> $argv"
    eval $argv
    if test $status -ne 0
        echo "FAILED: $argv"
        exit 1
    end
end

run_step cargo fmt
run_step cargo fmt --all -- --check
run_step cargo matrix clippy --all-targets -- -D warnings
run_step cargo matrix build

if test $run_tests = true
    run_step cargo matrix nextest run
    run_step cargo matrix test --doc -p libmoshpit
    if test $musl_unstable = true
        run_step cargo test --manifest-path libmoshpit/fuzz/Cargo.toml --features unstable
    else
        run_step cargo test --manifest-path libmoshpit/fuzz/Cargo.toml
    end
end

if test $run_docs = true
    run_step cargo doc -p libmoshpit
end

if test $run_coverage = true
    run_step cargo matrix -F unstable llvm-cov nextest --no-report
    run_step cargo llvm-cov report --lcov --output-path lcov.info
    run_step cargo llvm-cov report --html
end

if test $run_fuzz = true
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_frame -- -max_total_time=30
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_encframe -- -max_total_time=30
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_encframe_decrypt -- -max_total_time=30
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_escape_intercept -- -max_total_time=30
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_keyfile -- -max_total_time=30
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_emulator -- -max_total_time=30
    run_step cargo fuzz run --fuzz-dir libmoshpit/fuzz --features unstable fuzz_pubkey_parse -- -max_total_time=30
end

if test $run_install = true
    run_step (dirname (status filename))/run_install.fish
end

if test $run_musl = true
    if test $musl_unstable = true
        run_step (dirname (status filename))/run_musl.fish --unstable
    else
        run_step (dirname (status filename))/run_musl.fish
    end
end

if test $run_clean = true
    run_step cargo clean
end

echo ""
echo "All steps completed successfully."
