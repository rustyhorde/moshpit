complete -c mp -s c -l config-absolute-path -d 'Specify the absolute path to the config file' -r
complete -c mp -s t -l tracing-absolute-path -d 'Specify the absolute path to the tracing output file' -r
complete -c mp -s p -l private-key-path -d 'Specify the absolute path to the private key file' -r
complete -c mp -s k -l public-key-path -d 'Specify the absolute path to the public key file' -r
complete -c mp -s s -l server-port -d 'The port number of the server to connect to (default: 40404)' -r
complete -c mp -l predict -d 'Local-echo prediction: adaptive (default), always, or never' -r -f -a "adaptive\t''
always\t''
never\t''"
complete -c mp -l nat-warmup-count -d 'Number of NAT warmup keepalives to send (default: 3)' -r
complete -c mp -l diff-mode -d 'UDP diff transport mode: reliable (default), datagram, or statesync' -r -f -a "reliable\t''
datagram\t''
statesync\t''"
complete -c mp -l kex-algos -d 'Ordered KEX algorithms to offer, comma-separated [supported: x25519-sha256 (default), ml-kem-768-sha256, ml-kem-512-sha256, ml-kem-1024-sha256, p384-sha384, p256-sha256]' -r
complete -c mp -l aead-algos -d 'Ordered AEAD algorithms to offer, comma-separated [supported: aes256-gcm-siv (default), aes256-gcm, chacha20-poly1305, aes128-gcm-siv]' -r
complete -c mp -l mac-algos -d 'Ordered MAC algorithms to offer, comma-separated [supported: hmac-sha512 (default), hmac-sha256]' -r
complete -c mp -l kdf-algos -d 'Ordered KDF algorithms to offer, comma-separated [supported: hkdf-sha256 (default), hkdf-sha384, hkdf-sha512]' -r
complete -c mp -s v -l verbose -d 'Turn up logging verbosity (multiple will turn it up more)'
complete -c mp -s q -l quiet -d 'Turn down logging verbosity (multiple will turn it down more)'
complete -c mp -l nat-warmup -d 'Send NAT warmup keepalives at UDP session start (opt-in)'
complete -c mp -s h -l help -d 'Print help'
complete -c mp -s V -l version -d 'Print version'
