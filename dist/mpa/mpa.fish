# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_mpa_global_optspecs
	string join \n v/verbose q/quiet h/help V/version
end

function __fish_mpa_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_mpa_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_mpa_using_subcommand
	set -l cmd (__fish_mpa_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c mpa -n "__fish_mpa_needs_command" -s v -l verbose -d 'Turn up logging verbosity (multiple will turn it up more)'
complete -c mpa -n "__fish_mpa_needs_command" -s q -l quiet -d 'Turn down logging verbosity (multiple will turn it down more)'
complete -c mpa -n "__fish_mpa_needs_command" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_needs_command" -s V -l version -d 'Print version'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "start" -d 'Start the agent daemon'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "add-key" -d 'Add an identity key to the agent'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "list" -d 'List identities held by the agent'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "remove-key" -d 'Remove an identity from the agent'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "lock" -d 'Lock the agent (clear keys from memory)'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "unlock" -d 'Unlock the agent (reload keys from vault)'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "status" -d 'Show the running status of the agent daemon'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "stop" -d 'Stop the running agent daemon'
complete -c mpa -n "__fish_mpa_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mpa -n "__fish_mpa_using_subcommand start" -s s -l socket -d 'Override the Unix socket path (default: $XDG_RUNTIME_DIR/moshpit-agent-<uid>.sock)' -r
complete -c mpa -n "__fish_mpa_using_subcommand start" -l vault -d 'Path to the vault file (default: ~/.mp/agent-vault)' -r
complete -c mpa -n "__fish_mpa_using_subcommand start" -l shell -d 'Shell syntax for the exported MOSHPIT_AGENT_SOCK variable (fish or bash)' -r -f -a "fish\t''
bash\t''"
complete -c mpa -n "__fish_mpa_using_subcommand start" -l backend -d 'Unlock backend to use (passphrase, fido2, systemd-creds, ssh-agent-piggyback)' -r
complete -c mpa -n "__fish_mpa_using_subcommand start" -l foreground -d 'Run in the foreground instead of daemonizing'
complete -c mpa -n "__fish_mpa_using_subcommand start" -l passphrase-stdin -d 'Read the vault master passphrase from stdin instead of prompting'
complete -c mpa -n "__fish_mpa_using_subcommand start" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand add-key" -l passphrase-stdin -d 'Read the key passphrase from stdin instead of prompting'
complete -c mpa -n "__fish_mpa_using_subcommand add-key" -l no-hint -d 'Suppress the key-selection hint shown when multiple keys are loaded'
complete -c mpa -n "__fish_mpa_using_subcommand add-key" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand list" -l no-hint -d 'Suppress the key-selection hint shown when multiple keys are loaded'
complete -c mpa -n "__fish_mpa_using_subcommand list" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand remove-key" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand lock" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand unlock" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand status" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand stop" -l socket -d 'Override the Unix socket path (default: $MOSHPIT_AGENT_SOCK or XDG default)' -r
complete -c mpa -n "__fish_mpa_using_subcommand stop" -l shell -d 'Shell syntax for unsetting MOSHPIT_AGENT_SOCK (fish or bash)' -r -f -a "fish\t''
bash\t''"
complete -c mpa -n "__fish_mpa_using_subcommand stop" -s h -l help -d 'Print help'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "start" -d 'Start the agent daemon'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "add-key" -d 'Add an identity key to the agent'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "list" -d 'List identities held by the agent'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "remove-key" -d 'Remove an identity from the agent'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "lock" -d 'Lock the agent (clear keys from memory)'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "unlock" -d 'Unlock the agent (reload keys from vault)'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "status" -d 'Show the running status of the agent daemon'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "stop" -d 'Stop the running agent daemon'
complete -c mpa -n "__fish_mpa_using_subcommand help; and not __fish_seen_subcommand_from start add-key list remove-key lock unlock status stop help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
