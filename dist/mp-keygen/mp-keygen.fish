# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_mp_keygen_global_optspecs
    string join \n v/verbose q/quiet h/help V/version
end

function __fish_mp_keygen_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_mp_keygen_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_mp_keygen_using_subcommand
    set -l cmd (__fish_mp_keygen_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -s v -l verbose -d 'Turn up logging verbosity (multiple will turn it up more)'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -s q -l quiet -d 'Turn down logging verbosity (multiple will turn it down more)'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -s h -l help -d 'Print help'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -s V -l version -d 'Print version'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -f -a "generate" -d 'Generate a new identity public/private key pair'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -f -a "verify" -d 'Verify a public key fingerprint against a key file'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -f -a "fingerprint" -d 'Display the fingerprint of the given public key'
complete -c mp-keygen -n "__fish_mp_keygen_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -s o -l output-path -d 'Write keys to this path (skips the interactive path prompt)' -r
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -s k -l key-type -d 'Identity key algorithm: x25519 (default), p384, p256; with unstable: mldsa44, mldsa65, mldsa87' -r
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -s n -l no-passphrase -d 'Skip the passphrase prompt and create an unencrypted key'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -s f -l force -d 'Overwrite existing key files without confirmation'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -s s -l server -d 'Generate a server host key (allows unencrypted keys)'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -l passphrase-stdin -d 'Read passphrase from stdin instead of prompting'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand generate" -s h -l help -d 'Print help'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand verify" -s k -l key -d 'Path to the public key file' -r
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand verify" -s r -l randomart -d 'Also display the randomart image'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand verify" -s h -l help -d 'Print help'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand fingerprint" -s h -l help -d 'Print help'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand help; and not __fish_seen_subcommand_from generate verify fingerprint help" -f -a "generate" -d 'Generate a new identity public/private key pair'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand help; and not __fish_seen_subcommand_from generate verify fingerprint help" -f -a "verify" -d 'Verify a public key fingerprint against a key file'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand help; and not __fish_seen_subcommand_from generate verify fingerprint help" -f -a "fingerprint" -d 'Display the fingerprint of the given public key'
complete -c mp-keygen -n "__fish_mp_keygen_using_subcommand help; and not __fish_seen_subcommand_from generate verify fingerprint help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
