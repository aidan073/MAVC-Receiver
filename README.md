A receiver that processes packets from the Mobile Arm Vision Controller Sender [MAVC-Sender](https://github.com/aidan073/MAVC-Sender), and provides a convenient interface to connect the commands to your own control loop. See [MAVC-Example](https://github.com/aidan073/MAVC-Example) for example usage of this package.

## Local CA (mTLS)

By default, MAVC utilizes an unencrypted TCP connection and does not validate the client or server. The security package of this MAVC-Receiver package provides tooling that can create an on-disk CA to sign TLS certificates, a signed server cert, a signed client cert, and a CRL to manage revoked client certificates. Configuration of paths and lifetimes can be adjusted in [`cfg_examples/local_ca_cfg.yaml`](cfg_examples/local_ca_cfg.yaml) (every option is commented there).

### mTLS Step 1: CA + Server Certificate (Receiver)

1. Adjust `server_san_host` and `server_san_port` in the YAML so the server certificate SAN matches how clients reach the receiver.
2. From a working directory where you want the `ca_root` tree to live, run the installed CLI (after `pip install mavc_receiver`) or the module form:

```bash
mavc-local-ca cfg_examples/local_ca_cfg.yaml
# equivalent:
python -m mavc_receiver.security.setup cfg_examples/local_ca_cfg.yaml
```

The `mavc-local-ca` script invokes [`mavc_receiver.security.setup:main`](src/mavc_receiver/security/setup.py). This generates CA and server keys if needed, issues both certificates, records issuance in `index.txt` and `newcerts/`, and writes the CRL (default `ca/certs/ca.crl.pem`).

Run `mavc-local-ca --help` (or `python -m mavc_receiver.security.setup --help`) for subcommands (`crl`, `revoke`).

### [WARNING: As of 04/25/2026, the MAVC-Sender application is not yet configured for TLS, so the following steps will not work] mTLS Step 2: Signed Client Certificate (Client)

To connect to a receiver running with `verify_client_identity: true`, each client device must have:

1. **CA certificate pinned for server signature verification**
   - Copy `ca/certs/ca.cert.pem` (or your configured `ca_root` / `certs_subdir` / `ca_cert_file`) to the client.
   - Configure the client TLS trust store to trust that PEM for this receiver connection.

2. **A client keypair and certificate signed by the same CA**
   - Generate a private key and CSR on the client (or in secure provisioning).
   - Transfer that CSR to the CA machine using USB or another secure method.
   - Sign that CSR on the CA machine using `sign_client_csr()` from [`mavc_receiver.security.core.client`](src/mavc_receiver/security/core/client.py).
   - Install the signed client certificate and its private key on the device; ensure the certificate is used by MAVC-Sender (PROCESS TBD).
   Note: the issued serial is tracked in `index.txt` on the server for later revocation if needed.

### Revocation

The server should validate **client** certificates against the CRL during TLS. The CA cert, keys, and CRL stay on the server; clients do not need to download the CRL for that verification path.

| Command | Purpose |
|--------|---------|
| `mavc-local-ca <config.yaml> revoke <serial>` | Revoke by serial (decimal or hex, e.g. `4096` or `0x1000`). Updates `index.txt` and rewrites the CRL. Serial must exist for a cert issued by this CA. |
| `mavc-local-ca <config.yaml> crl` | Rebuild the CRL from `index.txt` (e.g. refresh `nextUpdate`). |

**Client key or cert compromised:** revoke that serial, issue a new client cert (new keypair) for the device.

**CA private key compromised:** create new CA key and certificate, re-issue server and all client certs, redistribute the new `ca.cert.pem` to every client.

**Server private key compromised:** since clients only pin the CA, a stolen server cert remains valid until expiry; rotating only the server cert under the same CA does not retire the old one. Full **CA rotation** and redistributing the new CA cert is the practical fix here. A future planned improvement is an **HTTP CRL endpoint** so clients could enforce server-cert revocation without rotating the CA.
