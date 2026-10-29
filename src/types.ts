/**
 * A DecodedCert represents an X.509 certificate the sections of an x509 certificate
 * that this extension supports viewing.
 */
export interface DecodedCert {
  subject: { name: string; value: string }[];
  issuer: { name: string; value: string }[];
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  signature: string;
  publicKey: {
    type: 'RSA' | 'ECDSA' | 'Unknown';
    algorithmOID: string;
    rsa?: {
      modulus: string; // hex or base64
      exponent: number;
    };
    ecdsa?: {
      curveOID: string;
      curveName?: string; // optional mapping
      publicKeyHex: string;
    };
  };
  fingerprint: string;
  isCA: boolean;
  selfSigned: boolean;
  subjectKeyId?: string;
  authorityKeyId?: string;
  caIssuers?: string[]; // URLs from Authority Information Access
  extensions?: {
    name: string;
    binaryValue: string;
    critical?: boolean;
  }[];
  decodedPem?: string;
}

/**
 * A certificate's position in a chain, and whether it came from the file or the trust store.
 */
export interface ChainEntry {
  cert: DecodedCert;
  role: 'leaf' | 'intermediate' | 'root';
  source: 'file' | 'trust-store';
  // Whether this certificate's signature verifies against its issuer (the next entry in the chain,
  // or itself for a self-signed root). Undefined when the issuer is not available.
  signatureVerified?: boolean;
}

/**
 * What the last certificate found in the file depends on.
 *  - self-signed: the file includes the root.
 *  - trust-store: the issuing root was found in the trust store and appended to the chain.
 *  - missing: the issuer could not be found (a missing intermediate, or an unknown root).
 */
export type ChainAnchor =
  | { kind: 'self-signed' }
  | { kind: 'trust-store' }
  | {
      kind: 'missing';
      issuer: { name: string; value: string }[];
      authorityKeyId?: string;
      caIssuers?: string[];
    };

/**
 * Certificates ordered from leaf to root.
 */
export interface CertChain {
  entries: ChainEntry[];
  anchor: ChainAnchor;
}

/**
 * Everything found in a PEM file.
 */
export interface PemReport {
  privateKeys: { type: string; encrypted: boolean }[];
  chains: CertChain[];
}

/**
 * ParsedExtension represents a parsed X.509 certificate extension.
 */
export interface ParsedExtension {
  name: string;
  oid: string;
  critical: boolean;
  type: string;
  parsed?: Record<string, any>;
  raw?: string;
  warnings?: string[];
}

/**
 * A mapping of common OIDs to their human-readable names.
 */
export const oidMap: Record<string, string> = {
  // Subject/Issuer attributes
  '2.5.4.3': 'Common Name (CN)',
  '2.5.4.10': 'Organization (O)',
  '2.5.4.11': 'Organizational Unit (OU)',
  '2.5.4.6': 'Country (C)',
  '2.5.4.7': 'Locality (L)',
  '2.5.4.8': 'State (S)',
  '1.2.840.113549.1.9.1': 'Email',

  // Public key algorithms
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.10045.2.1': 'ECDSA',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',

  // Signature algorithms
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',

  // Extensions
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.37': 'extendedKeyUsage',

  // Curves
  '1.2.840.10045.3.1.7': 'prime256v1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
};

/**
 * A mapping of extension OIDs to their internal type names.
 */
export const extensionOidMap: Record<string, string> = {
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.37': 'extendedKeyUsage',
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.35': 'authorityKeyIdentifier',
};
