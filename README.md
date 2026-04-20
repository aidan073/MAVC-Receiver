A receiver that processes packets from the Mobile Arm Vision Controller Sender [MAVC-Sender](https://github.com/aidan073/MAVC-Sender), and provides a convenient interface to connect the commands to your own control loop. See [MAVC-Example](https://github.com/aidan073/MAVC-Example) for example usage of this package.

## Local CA (mTLS)

By default, MAVC utilizes an unencrypted TCP connection and does not validate the client or server. The security package of this MAVC-Receiver package provides tooling that can create an on-disk CA to sign TLS certificates, a signed server cert, a signed client cert, and a CRL to manage revoked client certificates. Configuration of paths and lifetimes can be adjusted in [`cfg_examples/local_ca_cfg.yaml`](cfg_examples/local_ca_cfg.yaml) (every option is commented there).

### Set up the CA and server certificate

1. Adjust `server_san_host` and `server_san_port` in the YAML so the server certificate SAN matches how clients reach the receiver.
2. From a working directory where you want the `ca_root` tree to live, run the installed CLI (after `pip install mavc_receiver`) or the module form:

```bash
mavc-local-ca cfg_examples/local_ca_cfg.yaml
# equivalent:
python -m mavc_receiver.security.setup cfg_examples/local_ca_cfg.yaml
```

The `mavc-local-ca` script invokes [`mavc_receiver.security.setup:main`](src/mavc_receiver/security/setup.py). This generates CA and server keys if needed, issues both certificates, records issuance in `index.txt` and `newcerts/`, and writes the CRL (default `ca/certs/ca.crl.pem`).

Run `mavc-local-ca --help` (or `python -m mavc_receiver.security.setup --help`) for subcommands (`crl`, `revoke`).

### Todo: install the CA certificate on clients

- [ ] Copy `ca/certs/ca.cert.pem` (or your configured `ca_root` / `certs_subdir` / `ca_cert_file`) to each client.
- [ ] Point the client TLS trust store at that PEM as the sole trust anchor for this receiver (exact steps depend on your client).
- [ ] Keep the CA **private** key only on machines that issue or revoke certificates.

### Todo: obtain a signed client certificate

- [ ] On the client, create a keypair and a CSR for TLS client authentication (your environment’s method or OpenSSL).
- [ ] On the CA machine, sign the CSR with `sign_client_csr()` from [`mavc_receiver.security.core.client`](src/mavc_receiver/security/core/client.py). Load configuration with `load_local_ca_cfg()` from [`mavc_receiver.security.cfg_parser`](src/mavc_receiver/security/cfg_parser.py) (YAML path); that returns the process-wide `LocalCaCfg` singleton and its composed `paths`. Load the CA private key and certificate from disk, then pass them into `sign_client_csr()` together with the config. There is no CLI for client issuance yet.
- [ ] Install the issued client certificate and private key on the device. The serial will appear in `index.txt` for revocation.

### Revocation

The server should validate **client** certificates against the CRL during TLS. The CA cert, keys, and CRL stay on the server; clients do not need to download the CRL for that verification path.

| Command | Purpose |
|--------|---------|
| `mavc-local-ca <config.yaml> revoke <serial>` | Revoke by serial (decimal or hex, e.g. `4096` or `0x1000`). Updates `index.txt` and rewrites the CRL. Serial must exist for a cert issued by this CA. |
| `mavc-local-ca <config.yaml> crl` | Rebuild the CRL from `index.txt` (e.g. refresh `nextUpdate`). |

You can substitute `python -m mavc_receiver.security.setup` for `mavc-local-ca`. From Python, the matching pieces live in [`setup.py`](src/mavc_receiver/security/setup.py) (`setup_ca_system`, `main`), [`core/crl.py`](src/mavc_receiver/security/core/crl.py) (`write_crl`, `revoke_certificate`), and [`cfg_parser.py`](src/mavc_receiver/security/cfg_parser.py) (`load_local_ca_cfg`, `LocalCaCfg`, `LocalCaPaths`). The config and resolved paths are singletons for the process after the first successful `load_local_ca_cfg` call.

**Client key or cert compromised:** revoke that serial, reload or pick up the new CRL in the receiver, issue a new client cert (new keypair) for the device.

**CA private key compromised:** treat the PKI as burned—new CA key and certificate, re-issue server and all client certs, redistribute the new `ca.cert.pem` to every client.

**Server private key compromised:** if clients only pin the CA and cannot check server-leaf revocation, a stolen server cert remains valid until expiry; rotating only the server cert under the same CA does not retire the old one. Full **CA rotation** and redistributing the new CA cert is the practical fix here. A planned improvement is an **HTTP CRL endpoint** so clients could enforce server-cert revocation without rotating the CA.
