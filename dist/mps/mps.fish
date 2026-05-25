complete -c mps -s c -l config-absolute-path -d 'Specify the absolute path to the config file' -r
complete -c mps -s t -l tracing-absolute-path -d 'Specify the absolute path to the tracing output file' -r
complete -c mps -s p -l private-key-path -d 'Specify the absolute path to the private key file' -r
complete -c mps -s k -l public-key-path -d 'Specify the absolute path to the public key file' -r
complete -c mps -l warmup-delay-ms -d 'Extra delay (ms) after peer discovery before sending terminal data' -r
complete -c mps -l pacing-delay-us -d 'Min inter-packet delay (µs) between diff chunks [default: 1000]' -r
complete -c mps -l term-type -d 'TERM environment variable for spawned shells (default: xterm-256color)' -r
complete -c mps -l kex-algos -d 'Ordered KEX algorithms to prefer, comma-separated [supported: x25519-sha256 (default), ml-kem-768-sha256, ml-kem-512-sha256, ml-kem-1024-sha256, p384-sha384, p256-sha256]' -r
complete -c mps -l aead-algos -d 'Ordered AEAD algorithms to prefer, comma-separated [supported: aes256-gcm-siv (default), aes256-gcm, chacha20-poly1305, aes128-gcm-siv]' -r
complete -c mps -l mac-algos -d 'Ordered MAC algorithms to prefer, comma-separated [supported: hmac-sha512 (default), hmac-sha256]' -r
complete -c mps -l kdf-algos -d 'Ordered KDF algorithms to prefer, comma-separated [supported: hkdf-sha256 (default), hkdf-sha384, hkdf-sha512]' -r
complete -c mps -s v -l verbose -d 'Turn up logging verbosity (multiple will turn it up more)'
complete -c mps -s q -l quiet -d 'Turn down logging verbosity (multiple will turn it down more)'
complete -c mps -s e -l enable-std-output -d 'Enable logging to stdout/stderr'
complete -c mps -s h -l help -d 'Print help'
complete -c mps -s V -l version -d 'Print version'
