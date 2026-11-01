# Secure Communication Channel for Smart Metering Systems

Python reference implementation developed as part of a bachelor's thesis at HAW Hamburg. The project models communication between a Controllable Local System (CLS), a Smart Meter Gateway (SMGW), and a backend server. It compares transparent TCP forwarding with end-to-end TLS against a TLS-termination approach at the gateway.

## Project structure

The `codes` directory contains three implementation variants:

| Directory | Architecture | Connection initiation | TLS behaviour |
|---|---|---|---|
| `CLI/` | Transparent proxy, CLI scenario | CLS connects to SMGW | TLS is established between CLS and backend. The SMGW forwards the encrypted TLS stream. |
| `oldsrv/` | Transparent proxy, SRV scenario | SMGW connects to the CLS listening service | TLS is established between CLS and backend. The SMGW forwards the encrypted TLS stream. |
| `SRV/` | Initial TLS-termination prototype | CLS connects to SMGW | The SMGW terminates the CLS-facing TLS session, reads the plaintext, and sends it through a separate TLS session to the backend. |

**Note:** The directory named `SRV/` contains the TLS-termination prototype. The transparent SRV implementation is in `oldsrv/`.

## Technologies

- Python 3
- `socket` for TCP communication
- `ssl` for TLS and certificate-based authentication
- X.509 certificates in PEM format
- Threading for bidirectional forwarding in the transparent proxy variants
- Localhost-based testing

## Requirements

- Python 3.x
- No third-party Python packages are required by the supplied scripts; they use Python standard-library modules.

## Running the implementations

Open three separate terminals for each variant. Run the commands from the relevant variant directory so that the relative paths to the `certs/` directory resolve correctly.

### 1. Transparent CLI proxy (`CLI/`)

Start the components in this order:

```bash
python backend_server.py
python smgw_proxy.py
python cls_server.py
```

The scripts use the following local endpoints:

- SMGW proxy: `127.0.0.1:8443`
- Backend: `127.0.0.1:9443`

### 2. Transparent SRV proxy (`oldsrv/`)

Start the components in this order:

```bash
python backend_server.py
python cls_server.py
python smgw_proxy.py
```

The scripts use the following local endpoints:

- CLS listening service: `127.0.0.1:8555`
- Backend: `127.0.0.1:9443`

### 3. TLS-termination prototype (`SRV/`)

Start the components in this order:

```bash
python backend_server.py
python smgw_proxy.py
python cls_server.py
```

The scripts use the following local endpoints:

- SMGW TLS listener: `127.0.0.1:8443`
- Backend TLS listener: `127.0.0.1:9443`

## Certificates

Each implementation directory contains a `certs/` folder with the certificates and private keys used by the local test setup. The scripts load these files using relative paths. The certificates are intended only for this isolated demonstration environment.

**Security warning:** Do not publish or reuse the included private keys (`*.key`) or CA private key (`ca.key`). Generate new test credentials for your own environment. A real deployment requires protected key storage and certificate lifecycle management.

## Scope and limitations

This project is a local reference implementation for architectural comparison and functional demonstration. It does not constitute a production Smart Meter Gateway or a complete certification of standards compliance. The proxy control message in the supplied scripts is a simple text-based `CONNECT host port` message; it is not a complete implementation of the SOCKS5 wire protocol or the full SOCKS-TLS framing and state machine. The scripts also use fixed localhost addresses and ports and are designed for a small, sequential test setup rather than concurrent production workloads.

The transparent proxy variants forward the TLS byte stream without terminating the application TLS session at the SMGW. The termination prototype deliberately uses two separate TLS sessions and therefore exposes application plaintext within the SMGW process. These differences form the basis for the architectural and STRIDE security comparison in the thesis.

## Testing

The scripts print connection and data-reception messages to the terminal. A successful run can be checked by confirming that the backend receives the test payload. For the transparent variants, the application payload is protected by the TLS session between CLS and backend. In the termination prototype, the SMGW receives decrypted application data before forwarding it over the second TLS session.

## Thesis context

The implementation supports a comparison of three designs:

1. TLS termination at the SMGW (initial prototype).
2. Transparent TLS proxy with client-initiated connection (CLI).
3. Transparent TLS proxy with SMGW-initiated connection (SRV).

The security comparison uses STRIDE threat categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
