#!/usr/bin/env fish

set unstable false

for arg in $argv
    switch $arg
        case --unstable
            set unstable true
        case --help -h
            echo "Usage: run_musl.fish [OPTIONS]"
            echo ""
            echo "Builds Linux MUSL binaries via Docker and installs them to ~."
            echo ""
            echo "Options:"
            echo "  --unstable     Build with --features unstable instead of the stable build"
            echo "  --help, -h     Show this help message"
            exit 0
        case '*'
            echo "Unknown argument: $arg"
            echo "Run 'run_musl.fish --help' for usage."
            exit 1
    end
end

set release_dir target/x86_64-unknown-linux-musl/release
set bins mp mps mp-keygen mpa

function run_step
    echo ""
    echo "==> $argv"
    eval $argv
    if test $status -ne 0
        echo "FAILED: $argv"
        exit 1
    end
end

if test $unstable = true
    run_step docker run -v cargo-cache:/root/.cargo/registry -v (pwd):/home/rust/src -v ~/.gitconfig:/root/.gitconfig:ro --rm -t blackdex/rust-musl:x86_64-musl-stable cargo build --release --features unstable
else
    run_step docker run -v cargo-cache:/root/.cargo/registry -v (pwd):/home/rust/src -v ~/.gitconfig:/root/.gitconfig:ro --rm -t blackdex/rust-musl:x86_64-musl-stable cargo build --release
end

echo ""
echo "==> Fixing binary ownership"
for bin in $bins
    run_step sudo chown jozias:jozias $release_dir/$bin
end

echo ""
echo "==> Copying binaries to ~"
for bin in $bins
    run_step cp $release_dir/$bin ~
end

echo ""
echo "All MUSL build steps completed successfully."
