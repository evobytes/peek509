import * as tls from 'tls';
import { Certificate } from 'pkijs';
import { extractCertificatePems, findPrivateKeys, parseCertificate } from './decoder';
import { CertChain, ChainEntry, DecodedCert, PemReport } from './types';

interface ParsedCert {
  decoded: DecodedCert;
  cert: Certificate;
}

let trustStore: Promise<ParsedCert[]> | undefined;

/**
 * Loads Node's bundled (Mozilla) root CA store, used to find roots missing from the file.
 * Parsed once and cached.
 */
function loadTrustStore(): Promise<ParsedCert[]> {
  trustStore ??= Promise.all(
    tls.rootCertificates.map(pem => parseCertificate(pem).catch(() => undefined))
  ).then(roots => roots.filter((r): r is ParsedCert => !!r));
  return trustStore;
}

/**
 * Whether `issuer` could have issued `child`: the names match, and the key identifiers agree when both are present.
 */
function canIssue(issuer: ParsedCert, child: ParsedCert): boolean {
  if (!child.cert.issuer.isEqual(issuer.cert.subject)) {
    return false;
  }
  const aki = child.decoded.authorityKeyId;
  const ski = issuer.decoded.subjectKeyId;
  return !aki || !ski || aki === ski;
}

async function verifySignature(child: ParsedCert, issuer: ParsedCert): Promise<boolean> {
  try {
    return await child.cert.verify(issuer.cert);
  } catch {
    return false;
  }
}

function roleOf(decoded: DecodedCert): ChainEntry['role'] {
  if (decoded.selfSigned) {
    return 'root';
  }
  return decoded.isCA ? 'intermediate' : 'leaf';
}

/**
 * Orders certificates into chains, leaf first. Each chain starts at a certificate that did not issue
 * any other certificate in the file and follows issuers up to a self-signed root. If the top of the
 * chain is not self-signed, its issuer is looked up in the trust store, or reported as missing.
 * @param certs The certificates found in the file, in file order.
 * @param roots Trusted root certificates used to complete chains.
 */
export async function buildChains(certs: ParsedCert[], roots: ParsedCert[]): Promise<CertChain[]> {
  // Drop duplicate certificates, keeping the first occurrence.
  const unique = certs.filter(
    (c, i) => certs.findIndex(other => other.decoded.fingerprint === c.decoded.fingerprint) === i
  );

  const issuerOf = (c: ParsedCert) => (c.decoded.selfSigned ? undefined : unique.find(p => p !== c && canIssue(p, c)));

  const issuers = new Set(unique.map(issuerOf).filter(Boolean));
  let starts = unique.filter(c => !issuers.has(c));
  if (starts.length === 0 && unique.length > 0) {
    // Every certificate issued another (a cycle); start from the first one in the file.
    starts = [unique[0]];
  }

  const chains: CertChain[] = [];
  for (const start of starts) {
    const path: ParsedCert[] = [start];
    let next = issuerOf(start);
    while (next && !path.includes(next)) {
      path.push(next);
      next = issuerOf(next);
    }

    const entries: ChainEntry[] = path.map(c => ({ cert: c.decoded, role: roleOf(c.decoded), source: 'file' }));
    for (let i = 0; i < path.length - 1; i++) {
      entries[i].signatureVerified = await verifySignature(path[i], path[i + 1]);
    }

    const top = path[path.length - 1];
    let anchor: CertChain['anchor'];
    if (top.decoded.selfSigned) {
      anchor = { kind: 'self-signed' };
      entries[entries.length - 1].signatureVerified = await verifySignature(top, top);
    } else {
      const root = roots.find(r => canIssue(r, top));
      if (root) {
        entries[entries.length - 1].signatureVerified = await verifySignature(top, root);
        entries.push({ cert: root.decoded, role: 'root', source: 'trust-store' });
        anchor = { kind: 'trust-store' };
      } else {
        anchor = {
          kind: 'missing',
          issuer: top.decoded.issuer,
          authorityKeyId: top.decoded.authorityKeyId,
          caIssuers: top.decoded.caIssuers,
        };
      }
    }

    chains.push({ entries, anchor });
  }

  return chains;
}

/**
 * Decodes every certificate in a PEM file, orders them into chains, and notes any private keys.
 * @param pem The PEM file content.
 */
export async function decodePemFile(pem: string): Promise<PemReport> {
  const certPems = extractCertificatePems(pem);
  if (certPems.length === 0) {
    throw new Error('No PEM-encoded certificate found');
  }

  const certs = await Promise.all(certPems.map(parseCertificate));
  const chains = await buildChains(certs, await loadTrustStore());

  return { privateKeys: findPrivateKeys(pem), chains };
}
