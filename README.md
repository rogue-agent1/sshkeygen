# sshkeygen
SSH key management: list, generate, fingerprint, authorized_keys.
```bash
python sshkeygen.py list
python sshkeygen.py generate -t ed25519 -C "work@laptop"
python sshkeygen.py pubkey id_ed25519
python sshkeygen.py fingerprint ~/.ssh/id_rsa
python sshkeygen.py authorized list
```
## Zero dependencies. Python 3.6+.
