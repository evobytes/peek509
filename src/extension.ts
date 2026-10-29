import * as vscode from 'vscode';
import * as fs from 'fs';
import path from 'path';

import { decodePemFile } from './chain';
import { displayName, expiryStatus, formatReport, prettyPrintExtension, privateKeyNotice, roleLabel } from './decoder';
import { CertChain, ChainEntry, DecodedCert, PemReport, oidMap } from './types';

class Peek509ContentProvider implements vscode.TextDocumentContentProvider {
  private onDidChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
  public onDidChange = this.onDidChangeEmitter.event;

  private content: Map<string, string> = new Map();

  update(uri: vscode.Uri, content: string) {
    this.content.set(uri.toString(), content);
    this.onDidChangeEmitter.fire(uri);
  }

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.content.get(uri.toString()) || '';
  }
}

const contentProvider = new Peek509ContentProvider();

export async function activate(context: vscode.ExtensionContext) {
  // Register the content provider once
  vscode.workspace.registerTextDocumentContentProvider('peek509', contentProvider);

  /**
   * Register the decodeCert command.
   * If this command is run via right-click on a file in the file explorer, the file Uri will be passed in.
   * If Uri does not exist, the command was run from the command palette.
   */
  const peek509DecodeCertificate = vscode.commands.registerCommand('peek509.decodeCert', async (uri: vscode.Uri) => {
    if (!uri) {
      // Command palette - open a file dialog to let the user select a file to decode.
      const fileUri = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: { 'Certificate Files': ['pem', 'crt'] },
      });
      if (!fileUri || fileUri.length === 0) {
        vscode.window.showInformationMessage(
          'Peek509: To decode a certificate in your workspace, right-click a .pem or .crt file.'
        );
        return;
      }
      uri = fileUri[0];
    }

    try {
      const useWebView = vscode.workspace.getConfiguration('peek509').get('renderMode', 'webview') === 'webview';

      // Decode the certificates and show either in webview or text document.

      // Attempt to read the file then decode, order into chains and format the output.  Expects PEM format.
      const content = fs.readFileSync(uri.fsPath, 'utf8');
      const report = await decodePemFile(content);
      const formatted = formatReport(report);
      const decoded = `Decoded content for: ${path.basename(uri.fsPath)}\n\n` + formatted;

      if (useWebView) {
        // Show in webview
        const panel = vscode.window.createWebviewPanel('peek509Webview', 'Peek509 Viewer', vscode.ViewColumn.One, {
          enableScripts: true,
        });

        panel.webview.html = getWebviewContent(report);
      } else {
        // Create a Virtual Document Provider to display the results.
        vscode.workspace.registerTextDocumentContentProvider('peek509', {
          provideTextDocumentContent(uri: vscode.Uri): string {
            return decoded;
          },
        });

        // Display the results in a virtual document.
        const vUri = vscode.Uri.parse('peek509:' + path.basename(uri.fsPath) + '.decoded.txt');

        // Update the content provider with new content
        contentProvider.update(vUri, decoded);

        // Open or show the document
        const doc = await vscode.workspace.openTextDocument(vUri);
        await vscode.window.showTextDocument(doc, { preview: true });
      }
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to read file: ${err}`);
      return;
    }
  });

  context.subscriptions.push(peek509DecodeCertificate);
}

/**
 * Escapes text for safe inclusion in webview HTML.
 */
function esc(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderNameTable(attrs: { name: string; value: string }[]): string {
  return `<table class="w-full">
              ${attrs
                .map(attr => {
                  const label = oidMap[attr.name] ?? `OID ${attr.name}`;
                  return `<tr><td class="pr-2"><strong>${esc(label)}:</strong></td><td>${esc(attr.value)}</td></tr>`;
                })
                .join('')}
            </table>`;
}

function renderSignatureStatus(entry: ChainEntry): string {
  if (entry.signatureVerified === undefined) {
    return '';
  }
  return entry.signatureVerified
    ? '<span class="text-green-600" title="Signature verified against its issuer.">✓ signature verified</span>'
    : '<span class="text-red-600 font-semibold" title="Signature does not verify against its issuer.">✗ signature invalid</span>';
}

function renderExpiry(cert: DecodedCert): string {
  const expiry = expiryStatus(cert);
  return `<div class="expiry expiry-${expiry.state} text-xs" title="Not After: ${esc(String(cert.notAfter))}">${esc(
    expiry.text
  )}</div>`;
}

/**
 * Renders the chain overview: each certificate indented under the one it was issued by, ending with
 * what the top of the chain depends on.
 */
function renderChainOverview(chain: CertChain, chainIndex: number): string {
  const items = chain.entries.map(
    (entry, i) => `<li class="py-1" style="padding-left: ${i * 1.5}rem;">
          ${i > 0 ? '<span class="text-secondary">↳ issued by</span> ' : ''}
          <a href="#" class="chain-link font-medium" data-target="cert-${chainIndex}-${i}">[${i + 1}] ${esc(
      displayName(entry.cert.subject)
    )}</a>
          <span class="badge">${esc(roleLabel(entry))}</span>
          ${renderSignatureStatus(entry)}
          ${renderExpiry(entry.cert)}
        </li>`
  );

  const anchor = chain.anchor;
  if (anchor.kind === 'missing') {
    items.push(`<li class="py-1" style="padding-left: ${chain.entries.length * 1.5}rem;">
          <span class="text-secondary">↳ issued by</span>
          <div class="warning-box p-3 rounded mt-1">
            <p class="mb-2"><strong>⚠️ Missing certificate:</strong> the issuer is not in this file or the trust store.
            It may be a missing intermediate, or an untrusted root.</p>
            ${renderNameTable(anchor.issuer)}
            ${anchor.authorityKeyId ? `<p class="mt-2"><strong>Key Identifier:</strong> ${esc(anchor.authorityKeyId)}</p>` : ''}
            ${(anchor.caIssuers ?? [])
              .map(url => `<p class="mt-2"><strong>Download from:</strong> <code class="px-1">${esc(url)}</code></p>`)
              .join('')}
          </div>
        </li>`);
  }

  return `<ol class="section-box p-4 rounded text-sm mb-4">${items.join('')}</ol>`;
}

/**
 * Renders the full details of a single certificate.
 */
function renderCertificate(decodeCert: DecodedCert): string {
  return `
    <!-- Subject / Issuer -->
    <section class="mb-6">
      <div class="flex items-start align-top mb-4 space-x-4">
        <div class="flex-1">
          <h2 class="text-lg font-semibold mb-2">Subject</h2>
          <div class="section-box p-4 rounded text-sm">
            ${renderNameTable(decodeCert.subject)}
          </div>
        </div>
        <div class="flex-1">
          <h2 class="text-lg font-semibold mb-2">Issuer</h2>
          <div class="section-box p-4 rounded text-sm">
            ${renderNameTable(decodeCert.issuer)}
          </div>
        </div>
      </div>
    </section>

    <!-- Validity -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Validity</h2>
      <div class="section-box p-4 rounded text-sm">
        <p><strong>Not Before:</strong> ${decodeCert.notBefore}</p>
        <p><strong>Not After:</strong> ${decodeCert.notAfter}</p>
        ${
          decodeCert.notAfter < new Date()
            ? '<p class="text-red-600 font-semibold">This certificate has expired.</p>'
            : ''
        }
      </div>
    </section>

    <!-- Serial Number & Fingerprint -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Identifiers</h2>
      <div class="section-box p-4 rounded text-sm space-y-2">
        <p><strong>Serial Number:</strong> ${decodeCert.serialNumber}</p>
        <p><strong>SHA-256 Fingerprint:</strong> <span class="copyable cursor-pointer hover:opacity-80 rounded p-1" title="Click to copy fingerprint." style="background-color: var(--code-bg);">${
          decodeCert.fingerprint
        }</span></p>
      </div>
    </section>

    <!-- Public Key -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Public Key</h2>
      <div class="section-box p-4 rounded text-sm">
        ${
          decodeCert.publicKey.rsa
            ? `
            <details>
              <summary class="font-medium mb-3">RSA Details</summary>
              <p><strong>Type:</strong> RSA</p>
              <p class="mt-2"><strong>Modulus:</strong>
              <pre class="copyable p-2 rounded mt-2 cursor-pointer hover:opacity-80" title="Click to copy modulus.">${decodeCert.publicKey.rsa.modulus}</pre></p>
              <p class="mt-2"><strong>Exponent:</strong> ${decodeCert.publicKey.rsa.exponent}</p>
            </details>
            `
            : decodeCert.publicKey.ecdsa
            ? `
            <details>
              <summary class="font-medium mb-3">ECDSA Details</summary>
              <p><strong>Type:</strong> ECDSA</p> 
              <p class="mt-2"><strong>Curve OID:</strong> ${decodeCert.publicKey.ecdsa.curveOID}</p> 
              <p class="mt-2"><strong>Curve Name:</strong> ${decodeCert.publicKey.ecdsa.curveName ?? 'Unknown'}</p> 
              <p class="mt-2"><strong>Public Key (Hex):</strong></p>
              <pre class="copyable p-2 rounded mt-2 cursor-pointer hover:opacity-80" title="Click to copy public key.">${
                decodeCert.publicKey.ecdsa.publicKeyHex
              }</pre>
            </details>
            `
            : `<p>Unknown Public Key Type</p>`
        }
      </div>
    </section>

    <!-- Extensions -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Extensions</h2>
      ${
        decodeCert.extensions
          ?.map(
            ext => `<details class="section-box p-4 rounded text-sm mb-2">
          <summary class="font-medium">${ext.name}${
              ext.critical ? ' <span class="text-red-500">(critical)</span>' : ''
            }</summary>
          <div class="mt-3 pl-4">
            ${prettyPrintExtension(ext, 'html')}
          </div>
        </details>`
          )
          .join('\n') || '<p class="text-gray-500">No extensions found.</p>'
      }
    </section>

    <!-- PEM Content -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">PEM Content</h2>
      <pre class="copyable p-4 rounded text-sm overflow-x-auto w-full cursor-pointer hover:opacity-80" 
           title="Click to copy PEM content.">
${decodeCert.decodedPem ? esc(decodeCert.decodedPem) : ''}
      </pre>
    </section>`;
}

/**
 * Renders one chain: the overview, then each certificate in chain order (leaf first).
 */
function renderChain(chain: CertChain, chainIndex: number, chainCount: number): string {
  return `
    <section class="mb-8">
      <h2 class="text-xl font-bold mb-2">Certificate Chain${chainCount > 1 ? ` ${chainIndex + 1} of ${chainCount}` : ''}</h2>
      ${renderChainOverview(chain, chainIndex)}
      ${chain.entries
        .map(
          (entry, i) => `
      <details id="cert-${chainIndex}-${i}" class="cert-details mb-4"${i === 0 ? ' open' : ''}>
        <summary class="text-lg font-semibold mb-4">[${i + 1}] ${esc(displayName(entry.cert.subject))}
          <span class="badge">${esc(roleLabel(entry))}</span></summary>
        ${renderCertificate(entry.cert)}
      </details>`
        )
        .join('')}
    </section>`;
}

function getWebviewContent(report: PemReport): string {
  const keyNotice = privateKeyNotice(report);

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Peek509 Certificate Viewer</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --bg-primary: #ffffff;
      --bg-secondary: #f3f4f6;
      --text-primary: #1f2937;
      --text-secondary: #6b7280;
      --border-color: #e5e7eb;
      --accent-color: #2563eb;
      --accent-hover: #1d4ed8;
      --code-bg: #e5e7eb;
      --warn-bg: #fef9c3;
      --warn-border: #facc15;
    }

    /* VS Code sets a theme class on the webview body and updates it live when the editor theme changes. */
    body.vscode-dark,
    body.vscode-high-contrast {
      --bg-primary: #111827;
      --bg-secondary: #1f2937;
      --text-primary: #e5e7eb;
      --text-secondary: #9ca3af;
      --border-color: #374151;
      --accent-color: #60a5fa;
      --accent-hover: #3b82f6;
      --code-bg: #374151;
      --warn-bg: #422006;
      --warn-border: #a16207;
    }
    
    body {
      background-color: var(--bg-primary);
      color: var(--text-primary);
    }
    
    h1, h2 { color: var(--accent-color); }
    
    .section-box {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
    }

    .warning-box {
      background-color: var(--warn-bg);
      border: 1px solid var(--warn-border);
    }

    .text-secondary { color: var(--text-secondary); }

    .badge {
      display: inline-block;
      font-size: 0.75rem;
      font-weight: normal;
      padding: 0 0.5rem;
      margin-left: 0.25rem;
      border-radius: 9999px;
      border: 1px solid var(--accent-color);
      color: var(--accent-color);
    }

    .chain-link:hover { color: var(--accent-color); text-decoration: underline; }

    .expiry { margin-left: 1.25rem; }
    .expiry-valid { color: var(--accent-color); }
    .expiry-expiring { color: #d97706; font-weight: 600; }
    .expiry-expired { color: #dc2626; font-weight: 600; }

    .cert-details {
      border-top: 1px solid var(--border-color);
      padding-top: 1rem;
    }
    
    summary { cursor: pointer; }
    summary:hover { color: var(--accent-color); }
    
    code, pre {
      background-color: var(--code-bg);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
      word-break: break-all;
      white-space: pre-wrap;
    }
    
    table td { border-bottom: 1px solid var(--border-color); }
    table tr:last-child td { border-bottom: none; }
  </style>
</head>
<body class="font-sans">
  <div class="max-w-4xl mx-auto p-6">
    <h1 class="text-2xl font-bold mb-4">X.509 Certificates</h1>

    ${
      keyNotice
        ? `<div class="warning-box p-4 rounded text-sm mb-6"><strong>⚠️ Private key present:</strong> ${esc(keyNotice)}</div>`
        : ''
    }

    ${report.chains.map((chain, c) => renderChain(chain, c, report.chains.length)).join('')}
  </div>

  <script>
    document.querySelectorAll('.copyable').forEach(el => {
      el.addEventListener('click', () => navigator.clipboard.writeText(el.textContent.trim()));
    });

    // Chain overview links open and scroll to the certificate's details.
    document.querySelectorAll('.chain-link').forEach(link => {
      link.addEventListener('click', event => {
        event.preventDefault();
        const target = document.getElementById(link.dataset.target);
        target.open = true;
        target.scrollIntoView({ behavior: 'smooth' });
      });
    });
  </script>
</body>
</html>
  `;
}

export function deactivate() {}
