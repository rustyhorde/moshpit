complete -c mps -s c -l config-absolute-path -d 'Specify the absolute path to the config file' -r
complete -c mps -s t -l tracing-absolute-path -d 'Specify the absolute path to the tracing output file' -r
complete -c mps -s p -l private-key-path -d 'Specify the absolute path to the private key file' -r
complete -c mps -s k -l public-key-path -d 'Specify the absolute path to the public key file' -r
complete -c mps -s v -l verbose -d 'Turn up logging verbosity (multiple will turn it up more)'
complete -c mps -s q -l quiet -d 'Turn down logging verbosity (multiple will turn it down more)'
complete -c mps -s e -l enable-std-output -d 'Enable logging to stdout/stderr'
complete -c mps -s h -l help -d 'Print help'
complete -c mps -s V -l version -d 'Print version'
