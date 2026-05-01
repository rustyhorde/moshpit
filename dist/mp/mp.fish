complete -c mp -s c -l config-absolute-path -d 'Specify the absolute path to the config file' -r
complete -c mp -s t -l tracing-absolute-path -d 'Specify the absolute path to the tracing output file' -r
complete -c mp -s p -l private-key-path -d 'Specify the absolute path to the private key file' -r
complete -c mp -s k -l public-key-path -d 'Specify the absolute path to the public key file' -r
complete -c mp -s s -l server-port -d 'The port number of the server to connect to (default: 40404)' -r
complete -c mp -l predict -d 'Local-echo prediction: adaptive (default), always, or never' -r -f -a "adaptive\t''
always\t''
never\t''"
complete -c mp -s v -l verbose -d 'Turn up logging verbosity (multiple will turn it up more)'
complete -c mp -s q -l quiet -d 'Turn down logging verbosity (multiple will turn it down more)'
complete -c mp -s h -l help -d 'Print help'
complete -c mp -s V -l version -d 'Print version'
