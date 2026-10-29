# Peek509

**Peek509** is a lightweight VS Code extension that lets you decode and inspect X.509 certificates directly from `.pem` or `.crt` files. Right-click a certificate file or run the command from the palette to instantly view its contents in a clean, human-readable format. No terminal commands required.

---

## Features

![Peek509](media/example.gif)

### Certificate Decoding

- Decode `.pem` and `.crt` files via:
  - Right-click in Explorer
  - Command Palette (with file picker fallback)

- Supports manual ASN.1 parsing using `asn1js` and `pkijs`
- Handles RSA and ECDSA public keys, with future extensibility for EdDSA

### Webview Certificate Viewer (New in 1.3.0)

- Rich HTML UI powered by TailwindCSS
- Light/Dark theme follows your VS Code theme
- Collapsible sections for clean navigation
- Copy‑to‑clipboard buttons for long fields:
- SHA‑256 fingerprint
- RSA modulus
- EC public key
- SKI / AKI
- Other long extension values
- HTML formatters for supported X.509 extensions

### Text Based Viewer

- Optional plain‑text rendering mode (`peek509.renderMode`)
- Clean indentation and aligned formatting
- No save prompt — output opens in a virtual document

### Parsed Certificate Fields

- Subject and Issuer details (with OID mapping)
- Validity period
- Serial number
- SHA‑256 fingerprint
- Public key details (RSA/ECDSA)
- Parsed extensions:
  - `keyUsage`
  - `extendedKeyUsage`
  - `subjectKeyIdentifier`
  - `authorityKeyIdentifier`
  - `basicConstraints`
  - `subjectAltName`
  - Additional extensions where supported

## Usage

### Option 1: Right-click

- Open your project in VS Code.
- Right-click any `.pem` or `.crt` file in the Explorer.
- Select "**Peek509: Decode x509 Certificate**".
- View the decoded certificate in the Webview or text viewer (based on settings)

### Option 2: Command Palette

- Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
- Run "**Peek509: Decode x509 Certificate**".
- Select a certificate file from anywhere on your system.
- The decoded output will be displayed immediately

## Configuration

| Setting            | Description                                             |
| ------------------ | ------------------------------------------------------- |
| peek509.renderMode | Choose between `webview` (recommended) or `text` output |

## Installation

Search for **Peek509** in the [Visual Studio Marketplace](https://marketplace.visualstudio.com/) or install via the Extensions panel in VS Code.

---

## Roadmap

Planned enhancements for future versions:

- Multi‑certificate file support
- CSR and CRL decoding
- Decode PEM strings directly from highlighted text
- Certificate/key generation (RSA/ECDSA)
- Signature verification and trust chain visualization
- Export decoded certificate as JSON or PEM
- Dark‑mode auto‑detection
- Inline ASN.1 tree view for raw DER

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
