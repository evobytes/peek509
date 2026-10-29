import { fromBER, Sequence, Primitive } from 'asn1js';
import { ParsedExtension } from '../../types';
import { decodeExtensionAsn1 } from '../utils/decodeAsn1';

/**
 * Parses and decodes a Subject Alternative Name extension based on the definition in RFC 5280.
 *    SubjectAltName ::= GeneralNames
 *    GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *    GeneralName ::= CHOICE {
 *          otherName                       [0]     OtherName,
 *          rfc822Name                      [1]     IA5String,
 *          dNSName                         [2]     IA5String,
 *          x400Address                     [3]     ORAddress,
 *          directoryName                   [4]     Name,
 *          ediPartyName                    [5]     EDIPartyName,
 *          uniformResourceIdentifier       [6]     IA5String,
 *          iPAddress                       [7]     OCTET STRING,
 *          registeredID                    [8]     OBJECT IDENTIFIER
 *    }
 *
 * @param ext The extension to parse and decode.
 * @returns The parsed Subject Alternative Name extension.
 */
export function parseSubjectAltName(ext: { name: string; binaryValue: string; critical?: boolean }): ParsedExtension {
  const result: ParsedExtension = {
    name: 'Subject Alternative Name',
    oid: '2.5.29.17',
    critical: !!ext.critical,
    type: 'subjectAltName',
    parsed: {},
  };

  try {
    result.raw = ext.binaryValue;

    const { asn1, buffer, error } = decodeExtensionAsn1(ext.binaryValue);
    if (error || !asn1) {
      result.warnings = [error ?? 'Unknown decoding error'];
      result.raw = ext.binaryValue;
      return result;
    }

    const names = (asn1.valueBlock as any).value;
    const parsedNames: Record<string, string[]> = {};

    for (const name of names) {
      if (!(name instanceof Primitive)) {
        continue;
      }

      const tag = name.idBlock.tagNumber;
      const value = name.valueBlock.valueHexView.reduce((str, byte) => str + String.fromCharCode(byte), '');

      switch (tag) {
        case 1: // rfc822Name
          parsedNames.email = parsedNames.email || [];
          parsedNames.email.push(value);
          break;
        case 2: // dNSName
          parsedNames.dns = parsedNames.dns || [];
          parsedNames.dns.push(value);
          break;
        case 6: // URI
          parsedNames.uri = parsedNames.uri || [];
          parsedNames.uri.push(value);
          break;
        case 7: // IP
          parsedNames.ip = parsedNames.ip || [];
          parsedNames.ip.push(Array.from(name.valueBlock.valueHexView).join('.'));
          break;
        default:
          parsedNames.other = parsedNames.other || [];
          parsedNames.other.push(`Tag [${tag}]`);
      }
    }

    result.parsed = parsedNames;
  } catch (err) {
    result.warnings = ['Exception during SubjectAltName decoding'];
    result.raw = ext.binaryValue;
  }

  return result;
}
