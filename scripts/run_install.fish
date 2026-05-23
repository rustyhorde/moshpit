#!/usr/bin/env fish

function run_step
    echo ""
    echo "==> $argv"
    eval $argv
    if test $status -ne 0
        echo "FAILED: $argv"
        exit 1
    end
end

run_step cargo install --path moshpits --force --locked
run_step cargo install --path moshpit --force --locked
run_step cargo install --path keygen --force --locked
run_step cargo install --path agent --force --locked

echo ""
echo "All packages installed successfully."
