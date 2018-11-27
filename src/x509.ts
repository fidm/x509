'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { inspect } from 'util'
import { createHash } from 'crypto'
import { PEM, ASN1, Class, Tag, Template, Captures, BitString } from '@fidm/asn1'
import { bytesToIP, getOID, getOIDName } from './common'
import { publicKeyValidator, PublicKey } from './pki'

// short name OID mappings
const shortNames = Object.create(null)
shortNames.CN = getOID('commonName')
shortNames.commonName = 'CN'
shortNames.C = getOID('countryName')
shortNames.countryName = 'C'
shortNames.L = getOID('localityName')
shortNames.localityName = 'L'
shortNames.ST = getOID('stateOrProvinceName')
shortNames.stateOrProvinceName = 'ST'
shortNames.O = getOID('organizationName')
shortNames.organizationName = 'O'
shortNames.OU = getOID('organizationalUnitName')
shortNames.organizationalUnitName = 'OU'
shortNames.E = getOID('emailAddress')
shortNames.emailAddress = 'E'

function getShortName (name: string): string {
  return shortNames[name] == null ? '' : shortNames[name]
}

// validator for an X.509v3 certificate
const x509CertificateValidator: Template = {
  name: 'Certificate',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    name: 'Certificate.TBSCertificate',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    capture: 'tbsCertificate',
    value: [{
      name: 'Certificate.TBSCertificate.version',
      class: Class.CONTEXT_SPECIFIC,
      tag: Tag.NONE,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.version.integer',
        class: Class.UNIVERSAL,
        tag: Tag.INTEGER,
        capture: 'certVersion',
      }],
    }, {
      name: 'Certificate.TBSCertificate.serialNumber',
      class: Class.UNIVERSAL,
      tag: Tag.INTEGER,
      capture: 'certSerialNumber',
    }, {
      name: 'Certificate.TBSCertificate.signature',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      value: [{
        name: 'Certificate.TBSCertificate.signature.algorithm',
        class: Class.UNIVERSAL,
        tag: Tag.OID,
        capture: 'certinfoSignatureOID',
      }, {
        name: 'Certificate.TBSCertificate.signature.parameters',
        class: Class.UNIVERSAL,
        tag: Tag.OCTETSTRING,
        optional: true,
        capture: 'certinfoSignatureParams',
      }],
    }, {
      name: 'Certificate.TBSCertificate.issuer',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      capture: 'certIssuer',
    }, {
      name: 'Certificate.TBSCertificate.validity',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      value: [{
        name: 'Certificate.TBSCertificate.validity.notBefore',
        class: Class.UNIVERSAL,
        tag: [Tag.UTCTIME, Tag.GENERALIZEDTIME],
        capture: 'certValidityNotBefore',
      }, {
        name: 'Certificate.TBSCertificate.validity.notAfter',
        class: Class.UNIVERSAL,
        tag: [Tag.UTCTIME, Tag.GENERALIZEDTIME],
        capture: 'certValidityNotAfter',
      }],
    }, {
      // Name (subject) (RDNSequence)
      name: 'Certificate.TBSCertificate.subject',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      capture: 'certSubject',
    },
      // SubjectPublicKeyInfo
      publicKeyValidator,
    {
      // issuerUniqueID (optional)
      name: 'Certificate.TBSCertificate.issuerUniqueID',
      class: Class.CONTEXT_SPECIFIC,
      tag: Tag.BOOLEAN,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.issuerUniqueID.id',
        class: Class.UNIVERSAL,
        tag: Tag.BITSTRING,
        capture: 'certIssuerUniqueId',
      }],
    }, {
      // subjectUniqueID (optional)
      name: 'Certificate.TBSCertificate.subjectUniqueID',
      class: Class.CONTEXT_SPECIFIC,
      tag: Tag.INTEGER,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.subjectUniqueID.id',
        class: Class.UNIVERSAL,
        tag: Tag.BITSTRING,
        capture: 'certSubjectUniqueId',
      }],
    }, {
      // Extensions (optional)
      name: 'Certificate.TBSCertificate.extensions',
      class: Class.CONTEXT_SPECIFIC,
      tag: Tag.BITSTRING,
      capture: 'certExtensions',
      optional: true,
    }],
  }, {
    // AlgorithmIdentifier (signature algorithm)
    name: 'Certificate.signatureAlgorithm',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    value: [{
      // algorithm
      name: 'Certificate.signatureAlgorithm.algorithm',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
      capture: 'certSignatureOID',
    }, {
      name: 'Certificate.TBSCertificate.signature.parameters',
      class: Class.UNIVERSAL,
      tag: Tag.OCTETSTRING,
      optional: true,
      capture: 'certSignatureParams',
    }],
  }, {
    name: 'Certificate.signatureValue',
    class: Class.UNIVERSAL,
    tag: Tag.BITSTRING,
    capture: 'certSignature',
  }],
}
// validator for a x509 CSR
const x509CertificateSigningRequestValidator = {
  name: 'CertificateSigningRequest',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
          name: 'Certificate.TBSCertificate',
          class: Class.UNIVERSAL,
          tag: Tag.SEQUENCE,
          capture: 'tbsCertificate',
          value: [{
                  name: 'Certificate.TBSCertificate.version',
                  class: Class.CONTEXT_SPECIFIC,
                  tag: Tag.NONE,
                  optional: true,
                  value: [{
                          name: 'Certificate.TBSCertificate.version.integer',
                          class: Class.UNIVERSAL,
                          tag: Tag.INTEGER,
                          capture: 'certVersion',
                      }],
              }, {
                  name: 'Certificate.TBSCertificate.serialNumber',
                  class: Class.UNIVERSAL,
                  tag: Tag.INTEGER,
                  capture: 'certSerialNumber',
              }, {
                  name: 'Certificate.TBSCertificate.issuer',
                  class: Class.UNIVERSAL,
                  tag: Tag.SEQUENCE,
                  capture: 'certIssuer',
              }, {
                  // Name (subject) (RDNSequence)
                  name: 'Certificate.TBSCertificate.subject',
                  class: Class.UNIVERSAL,
                  tag: Tag.SEQUENCE,
                  capture: 'certSubject',
              }, {
                  // subjectUniqueID (optional)
                  name: 'Certificate.TBSCertificate.subjectUniqueID',
                  class: Class.CONTEXT_SPECIFIC,
                  tag: Tag.INTEGER,
                  optional: true,
                  value: [{
                          name: 'Certificate.TBSCertificate.subjectUniqueID.id',
                          class: Class.UNIVERSAL,
                          tag: Tag.BITSTRING,
                          capture: 'certSubjectUniqueId',
                      }],
              }, {
                  // Extensions (optional)
                  name: 'Certificate.TBSCertificate.extensionRequest',
                  class: Class.CONTEXT_SPECIFIC,
                  tag: Tag.NONE,
                  value: [{
                    name: 'Certificate.TBSCertificate.extensionRequest',
                    class: Class.UNIVERSAL,
                    tag: Tag.SEQUENCE,
                    value: [{
                      name: 'Certificate.TBSCertificate.extensionRequestt',
                      class: Class.UNIVERSAL,
                      tag: Tag.OID,
                    },
                    {
                      name: 'Certificate.TBSCertificate.extensionRequest',
                      class: Class.UNIVERSAL,
                      tag: Tag.SET,
                      capture: 'certExtensions',
                    }]
                  }],
                  optional: true,
              }],
      }, {
          // AlgorithmIdentifier (signature algorithm)
          name: 'Certificate.signatureAlgorithm',
          class: Class.UNIVERSAL,
          tag: Tag.SEQUENCE,
          value: [{
                  // algorithm
                  name: 'Certificate.signatureAlgorithm.algorithm',
                  class: Class.UNIVERSAL,
                  tag: Tag.OID,
                  capture: 'certSignatureOID',
              }, {
                  name: 'Certificate.TBSCertificate.signature.parameters',
                  class: Class.UNIVERSAL,
                  tag: Tag.OCTETSTRING,
                  optional: true,
                  capture: 'certSignatureParams',
              }],
      }, {
          name: 'Certificate.signatureValue',
          class: Class.UNIVERSAL,
          tag: Tag.BITSTRING,
          capture: 'certSignature',
      }],
};

/**
 * Attribute for X.509v3 certificate.
 */
export interface Attribute {
  oid: string,
  value: any,
  valueTag: Tag,
  name: string,
  shortName: string,
  extensions?: Extension[]
}

/**
 * DistinguishedName for X.509v3 certificate.
 */
export class DistinguishedName {
  uniqueId: BitString | null
  attributes: Attribute[]
  constructor () {
    this.attributes = []
    this.uniqueId = null
  }

  get commonName (): string {
    return this.getFieldValue('commonName')
  }

  get organizationName (): string {
    return this.getFieldValue('organizationName')
  }

  get organizationalUnitName (): string {
    return this.getFieldValue('organizationalUnitName')
  }

  get countryName (): string {
    return this.getFieldValue('countryName')
  }

  get localityName (): string {
    return this.getFieldValue('localityName')
  }

  get serialName (): string {
    return this.getFieldValue('serialName')
  }

  getHash (): Buffer {
    const hasher = createHash('sha1')
    for (const attr of this.attributes) {
      hasher.update(attr.oid)
      hasher.update(attr.value)
    }
    return hasher.digest()
  }

  getField (key: string): Attribute | null {
    for (const attr of this.attributes) {
      if (key === attr.oid || key === attr.name || key === attr.shortName) {
        return attr
      }
    }
    return null
  }

  addField (attr: any) {
    fillMissingFields([attr])
    this.attributes.push(attr)
  }

  setAttrs (attrs: any) {
    // set new attributes, clear hash
    fillMissingFields(attrs)
    this.attributes = attrs
  }

  toJSON () {
    const obj = {} as any
    for (const attr of this.attributes) {
      const key = attr.shortName
      if (typeof key === 'string' && key !== '') {
        obj[key] = attr.value
      }
    }
    obj.uniqueId = this.uniqueId
    obj.attributes = this.attributes
    return obj
  }

  private getFieldValue (key: string): string {
    const val = this.getField(key)
    if (val != null) {
      return val.value
    }
    return ''
  }
}

export abstract class X509 {
  readonly captures: Captures
  readonly raw: Buffer
  readonly version: number
  readonly serialNumber: string
  readonly signatureOID: string
  readonly signatureAlgorithm: string
  readonly signature: Buffer
  readonly subjectKeyIdentifier: string
  readonly ocspServer: string
  readonly issuingCertificateURL: string
  readonly isCA: boolean
  readonly maxPathLen: number
  readonly basicConstraintsValid: boolean
  readonly keyUsage: number
  readonly dnsNames: string[]
  readonly emailAddresses: string[]
  readonly ipAddresses: string[]
  readonly uris: string[]
  readonly issuer: DistinguishedName
  readonly extensions: Extension[]
  readonly tbsCertificate: ASN1
  readonly subject: DistinguishedName

  constructor(validator: Template, obj: ASN1) {
    this.captures = Object.create(null) as Captures
    // validate certificate and capture data
    const err = obj.validate(validator, this.captures)
    if (err != null) {
      throw new Error('Cannot read X.509 certificate: ' + err.message)
    }

    this.raw = obj.DER
    this.version = this.captures.certVersion == null ? 0 : (ASN1.parseIntegerNum(this.captures.certVersion.bytes) + 1)
    this.serialNumber = ASN1.parseIntegerStr(this.captures.certSerialNumber.bytes)
    this.signatureOID = ASN1.parseOID(this.captures.certSignatureOID.bytes)
    this.signatureAlgorithm = getOIDName(this.signatureOID)

    this.signature = ASN1.parseBitString(this.captures.certSignature.bytes).buf

    this.issuer = new DistinguishedName()
    this.issuer.setAttrs(RDNAttributesAsArray(this.captures.certIssuer))
    if (this.captures.certIssuerUniqueId != null) {
      this.issuer.uniqueId = ASN1.parseBitString(this.captures.certIssuerUniqueId.bytes)
    }

    this.extensions = []
    this.subjectKeyIdentifier = ''
    this.ocspServer = ''
    this.issuingCertificateURL = ''
    this.isCA = false
    this.maxPathLen = -1
    this.basicConstraintsValid = false
    this.keyUsage = 0
    this.dnsNames = []
    this.emailAddresses = []
    this.ipAddresses = []
    this.uris = []
    if (this.captures.certExtensions != null) {
      this.extensions = certificateExtensionsFromAsn1(this.captures.certExtensions)
      for (const ext of this.extensions) {
        if (typeof ext.subjectKeyIdentifier === 'string') {
          this.subjectKeyIdentifier = ext.subjectKeyIdentifier
        }
        if (typeof ext.authorityInfoAccessOcsp === 'string') {
          this.ocspServer = ext.authorityInfoAccessOcsp
        }
        if (typeof ext.authorityInfoAccessIssuers === 'string') {
          this.issuingCertificateURL = ext.authorityInfoAccessIssuers
        }
        if (typeof ext.basicConstraintsValid === 'boolean') {
          this.isCA = ext.isCA
          this.maxPathLen = ext.maxPathLen
          this.basicConstraintsValid = ext.basicConstraintsValid
        }
        if (typeof ext.keyUsage === 'number') {
          this.keyUsage = ext.keyUsage
        }

        if (Array.isArray(ext.altNames)) {
          for (const item of ext.altNames) {
            if (item.dnsName != null) {
              this.dnsNames.push(item.dnsName)
            }
            if (item.email != null) {
              this.emailAddresses.push(item.email)
            }
            if (item.ip != null) {
              this.ipAddresses.push(item.ip)
            }
            if (item.uri != null) {
              this.uris.push(item.uri)
            }
          }
        }
      }
    }

    this.subject = new DistinguishedName()
    try {
      this.subject.setAttrs(RDNAttributesAsArray(this.captures.certSubject))
      if (this.captures.certSubjectUniqueId != null) {
        this.subject.uniqueId = ASN1.parseBitString(this.captures.certSubjectUniqueId.bytes)
      }
    } catch (e) {
      console.debug("Could not read cert subject: " + e.message);
    }

    this.tbsCertificate = this.captures.tbsCertificate
  }

  /**
   * Gets an extension by its name or oid.
   * If extension exists and a key provided, it will return extension[key].
   * ```js
   * certificate.getExtension('keyUsage')
   * certificate.getExtension('2.5.29.15')
   * // => { oid: '2.5.29.15',
   * //      critical: true,
   * //      value: <Buffer 03 02 05 a0>,
   * //      name: 'keyUsage',
   * //      digitalSignature: true,
   * //      nonRepudiation: false,
   * //      keyEncipherment: true,
   * //      dataEncipherment: false,
   * //      keyAgreement: false,
   * //      keyCertSign: false,
   * //      cRLSign: false,
   * //      encipherOnly: false,
   * //      decipherOnly: false }
   * certificate.getExtension('keyUsage', 'keyCertSign') // => false
   * ```
   * @param name extension name or OID
   * @param key key in extension
   */
  getExtension (name: string, key: string = ''): any {
    for (const ext of this.extensions) {
      if (name === ext.oid || name === ext.name) {
        return key === '' ? ext : ext[key]
      }
    }
    return null
  }

  /**
   * Return a friendly JSON object for debuging.
   */
  toJSON (): any {
    const obj = {} as any
    for (const key of Object.keys(this)) {
      obj[key] = toJSONify((this as any)[key])
    }
    delete obj.tbsCertificate
    delete obj.captures
    return obj
  }

  protected [inspect.custom] (_depth: any, options: any): string {
    if (options.depth <= 2) {
      options.depth = 10
    }
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

/**
 * X.509v3 Certificate.
 */
export class Certificate extends X509 {
  /**
   * Parse one or more X.509 certificates from PEM formatted buffer.
   * If there is no certificate, it will throw error.
   * @param data PEM formatted buffer
   */
  static fromPEMs (data: Buffer): Certificate[] {
    const certs = []
    const pems = PEM.parse(data)

    for (const pem of pems) {
      if (pem.type !== 'CERTIFICATE' &&
        pem.type !== 'X509 CERTIFICATE' &&
        pem.type !== 'TRUSTED CERTIFICATE') {
        throw new Error('Could not convert certificate from PEM: invalid type')
      }
      if (pem.procType.includes('ENCRYPTED')) {
        throw new Error('Could not convert certificate from PEM: PEM is encrypted.')
      }

      const obj = ASN1.fromDER(pem.body)
      certs.push(new Certificate(obj))
    }
    if (certs.length === 0) {
      throw new Error('No Certificate')
    }
    return certs
  }

  /**
   * Parse an X.509 certificate from PEM formatted buffer.
   * @param data PEM formatted buffer
   */
  static fromPEM (data: Buffer): Certificate {
    return Certificate.fromPEMs(data)[0]
  }

  readonly infoSignatureOID: string
  readonly authorityKeyIdentifier: string
  readonly validFrom: Date
  readonly validTo: Date
  readonly publicKey: PublicKey
  readonly publicKeyRaw: Buffer

  /**
   * Creates an X.509 certificate from an ASN.1 object
   * @param obj an ASN.1 object
   */
  constructor (obj: ASN1) {
    super(x509CertificateValidator, obj);

    this.infoSignatureOID = ASN1.parseOID(this.captures.certinfoSignatureOID.bytes)

    this.authorityKeyIdentifier = ''

    this.validFrom = ASN1.parseTime(this.captures.certValidityNotBefore.tag, this.captures.certValidityNotBefore.bytes)
    this.validTo = ASN1.parseTime(this.captures.certValidityNotAfter.tag, this.captures.certValidityNotAfter.bytes)

    for (const ext of this.extensions) {
      if (typeof ext.authorityKeyIdentifier === 'string') {
        this.authorityKeyIdentifier = ext.authorityKeyIdentifier
      }
    }

    this.publicKey = new PublicKey(this.captures.publicKeyInfo)
    this.publicKeyRaw = this.publicKey.toDER()
  }

  /**
   * Returns null if a subject certificate is valid, or error if invalid.
   * Note that it does not check validity time, DNS name, ip or others.
   * @param child subject's Certificate
   */
  checkSignature (child: Certificate): Error | null {
    // RFC 5280, 4.2.1.9:
    // "If the basic constraints extension is not present in a version 3
    // certificate, or the extension is present but the cA boolean is not
    // asserted, then the certified public key MUST NOT be used to verify
    // certificate signatures."
    // (not handler entrust broken SPKI, See http://www.entrust.net/knowledge-base/technote.cfm?tn=7869)
    if (this.version === 3 && !this.basicConstraintsValid || (this.basicConstraintsValid && !this.isCA)) {
        return new Error('The parent constraint violation error')
    }

    if (this.getExtension('keyUsage', 'keyCertSign') !== true) {
      return new Error('The parent constraint violation error')
    }

    if (!child.isIssuer(this)) {
      return new Error('The parent certificate did not issue the given child certificate')
    }

    const agl = getHashAgl(child.signatureOID)
    if (agl === '') {
      return new Error('Unknown child signature OID.')
    }

    const res = this.publicKey.verify(child.tbsCertificate.DER, child.signature, agl)
    if (res === false) {
      return new Error('Child signature not matched')
    }
    return null
  }

  /**
   * Returns true if this certificate's issuer matches the passed
   * certificate's subject. Note that no signature check is performed.
   * @param parent issuer's Certificate
   */
  isIssuer (parent: Certificate): boolean {
    return this.issuer.getHash().equals(parent.subject.getHash())
  }

  /**
   * Verifies the subjectKeyIdentifier extension value for this certificate
   * against its public key.
   */
  verifySubjectKeyIdentifier (): boolean {
    const ski = this.publicKey.getFingerprint('sha1', 'PublicKey')
    return ski.toString('hex') === this.subjectKeyIdentifier
  }
}

/**
 * X.509v3 Certificate.
 */
export class CertificateSigningRequest extends X509 {
  /**
   * Parse one or more X.509 certificates from PEM formatted buffer.
   * If there is no certificate, it will throw error.
   * @param data PEM formatted buffer
   */
  static fromPEMs (data: Buffer): CertificateSigningRequest[] {
    const certRequests = []
    const pems = PEM.parse(data)

    for (const pem of pems) {
      if (pem.type !== 'CERTIFICATE REQUEST') {
        throw new Error('Could not convert certificate signing request from PEM: invalid type')
      }

      const obj = ASN1.fromDER(pem.body)
      certRequests.push(new CertificateSigningRequest(obj))
    }
    if (certRequests.length === 0) {
      throw new Error('No Certificate request')
    }
    return certRequests
  }

  /**
   * Parse an X.509 certificate signing request from PEM formatted buffer.
   * @param data PEM formatted buffer
   */
  static fromPEM (data: Buffer): CertificateSigningRequest {
    return CertificateSigningRequest.fromPEMs(data)[0]
  }
  /**
   * Creates an X.509 certificate signing from an ASN.1 object
   * @param obj an ASN.1 object
   */
  constructor (obj: ASN1) {
    super(x509CertificateSigningRequestValidator, obj);
  }
}

export interface Extension {
  oid: string
  critical: boolean
  value: Buffer
  name: string
  altNames?: any[]
  [index: string]: any
}

function certificateExtensionsFromAsn1 (exts: ASN1): Extension[] {
  const res = []
  for (const val of exts.mustCompound()) {
    for (const ext of val.mustCompound()) {
      res.push(certificateExtensionFromAsn1(ext))
    }
  }

  return res
}

function certificateExtensionFromAsn1 (ext: ASN1): Extension {
  // an extension has:
  // [0] extnID      OBJECT IDENTIFIER
  // [1] critical    BOOLEAN DEFAULT FALSE
  // [2] extnValue   OCTET STRING
  const e = {} as Extension
  e.oid = ASN1.parseOID(ext.value[0].bytes)
  e.critical = false

  if (ext.value[1].tag === Tag.BOOLEAN) {
    e.critical = ASN1.parseBool(ext.value[1].bytes)
    e.value = ext.value[2].bytes
  } else {
    e.value = ext.value[1].bytes
  }

  // if the oid is known, get its name
  e.name = getOIDName(e.oid)
  switch (e.name) {
    // handle key usage
  case 'keyUsage':
    decodeExtKeyUsage(e)
    break
  case 'basicConstraints':
    decodeExtBasicConstraints(e)
    break
  case 'extKeyUsage':
    decodeExtExtKeyUsage(e)
    break
  case 'nsCertType':
    decodeExtNsCertType(e)
    break
  case 'subjectAltName':
    decodeExtAltName(e)
    break
  case 'issuerAltName':
    decodeExtAltName(e)
    break
  case 'subjectKeyIdentifier':
    decodeExtSubjectKeyIdentifier(e)
    break
  case 'authorityKeyIdentifier':
    decodeExtAuthorityKeyIdentifier(e)
    break
  case 'authorityInfoAccess':
    decodeExtAuthorityInfoAccess(e)
    break
  }
  return e
}

function decodeExtKeyUsage (e: Extension) {
  // ev is a BITSTRING
  const ev = ASN1.parseBitString(ASN1.fromDER(e.value).bytes)
  let b2 = 0x00
  let b3 = 0x00

  e.keyUsage = 0
  for (let i = 0; i < 9; i++) {
    if (ev.at(i) !== 0) {
      e.keyUsage |= 1 << i
    }
  }

  if (ev.buf.length > 0) {
    b2 = ev.buf[0]
    b3 = ev.buf.length > 1 ? ev.buf[1] : 0
  }
  // set flags
  e.digitalSignature = (b2 & 0x80) === 0x80
  e.nonRepudiation = (b2 & 0x40) === 0x40
  e.keyEncipherment = (b2 & 0x20) === 0x20
  e.dataEncipherment = (b2 & 0x10) === 0x10
  e.keyAgreement = (b2 & 0x08) === 0x08
  e.keyCertSign = (b2 & 0x04) === 0x04
  e.cRLSign = (b2 & 0x02) === 0x02
  e.encipherOnly = (b2 & 0x01) === 0x01
  e.decipherOnly = (b3 & 0x80) === 0x80
}

function decodeExtBasicConstraints (e: Extension) {
  // handle basic constraints
  // get value as SEQUENCE
  const ev = ASN1.fromDER(e.value)
  const vals = ev.mustCompound()
  // get cA BOOLEAN flag (defaults to false)
  if (vals.length > 0 && vals[0].tag === Tag.BOOLEAN) {
    e.isCA = ASN1.parseBool(vals[0].bytes)
  } else {
    e.isCA = false
  }
  // get path length constraint
  let value = null
  if (vals.length > 0 && vals[0].tag === Tag.INTEGER) {
    value = vals[0].bytes
  } else if (vals.length > 1) {
    value = vals[1].bytes
  }

  if (value !== null) {
    e.maxPathLen = ASN1.parseInteger(value)
  } else {
    e.maxPathLen = -1
  }
  e.basicConstraintsValid = true
}

function decodeExtExtKeyUsage (e: Extension) {
  // handle extKeyUsage
  // value is a SEQUENCE of OIDs
  const ev = ASN1.fromDER(e.value)
  const vals = ev.mustCompound()
  for (const val of vals) {
    e[getOIDName(ASN1.parseOID(val.bytes))] = true
  }
}

function decodeExtNsCertType (e: Extension) {
  // ev is a BITSTRING
  const ev = ASN1.parseBitString(ASN1.fromDER(e.value).bytes)
  let b2 = 0x00
  if (ev.buf.length > 0) {
    b2 = ev.buf[0]
  }
  // set flags
  e.client = (b2 & 0x80) === 0x80
  e.server = (b2 & 0x40) === 0x40
  e.email = (b2 & 0x20) === 0x20
  e.objsign = (b2 & 0x10) === 0x10
  e.reserved = (b2 & 0x08) === 0x08
  e.sslCA = (b2 & 0x04) === 0x04
  e.emailCA = (b2 & 0x02) === 0x02
  e.objCA = (b2 & 0x01) === 0x01
}

function decodeExtAltName (e: Extension) {
  // handle subjectAltName/issuerAltName
  e.altNames = []

  // ev is a SYNTAX SEQUENCE
  const ev = ASN1.fromDER(e.value)
  const vals = ev.mustCompound()
  for (const gn of vals) {
    // get GeneralName
    const item: any = {
      tag: gn.tag,
      value: gn.bytes,
    }
    e.altNames.push(item)

    switch (gn.tag) {
    // rfc822Name, emailAddresses
    case 1:
      item.email = gn.bytes.toString()
      break
    // dNSName
    case 2:
      item.dnsName = gn.bytes.toString()
      break
    // uniformResourceIdentifier (URI)
    case 6:
      item.uri = gn.bytes.toString()
      break
    // IPAddress
    case 7:
      // convert to IPv4/IPv6 string representation
      item.ip = bytesToIP(gn.bytes)
      break
    // registeredID
    case 8:
      item.oid = ASN1.parseOID(gn.bytes)
      break
    default:
      // unsupported
    }
  }
}

const subjectKeyIdentifierValidator: Template = {
  name: 'subjectKeyIdentifier',
  class: Class.UNIVERSAL,
  tag: Tag.OCTETSTRING,
  capture: 'subjectKeyIdentifier',
}

function decodeExtSubjectKeyIdentifier (e: Extension) {
  const captures = ASN1.parseDERWithTemplate(e.value, subjectKeyIdentifierValidator)
  e.subjectKeyIdentifier = captures.subjectKeyIdentifier.bytes.toString('hex')
}

const authorityKeyIdentifierValidator: Template = {
  name: 'authorityKeyIdentifier',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    name: 'authorityKeyIdentifier.value',
    class: Class.CONTEXT_SPECIFIC,
    tag: Tag.NONE,
    capture: 'authorityKeyIdentifier',
  }],
}

function decodeExtAuthorityKeyIdentifier (e: Extension) {
  const captures = ASN1.parseDERWithTemplate(e.value, authorityKeyIdentifierValidator)
  e.authorityKeyIdentifier = captures.authorityKeyIdentifier.bytes.toString('hex')
}

const authorityInfoAccessValidator: Template = {
  name: 'authorityInfoAccess',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    name: 'authorityInfoAccess.authorityInfoAccessOcsp',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    optional: true,
    value: [{
      name: 'authorityInfoAccess.authorityInfoAccessOcsp.oid',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
    }, {
      name: 'authorityInfoAccess.authorityInfoAccessOcsp.value',
      class: Class.CONTEXT_SPECIFIC,
      tag: Tag.OID,
      capture: 'authorityInfoAccessOcsp',
    }],
  }, {
    name: 'authorityInfoAccess.authorityInfoAccessIssuers',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    optional: true,
    value: [{
      name: 'authorityInfoAccess.authorityInfoAccessIssuers.oid',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
    }, {
      name: 'authorityInfoAccess.authorityInfoAccessIssuers.value',
      class: Class.CONTEXT_SPECIFIC,
      tag: Tag.OID,
      capture: 'authorityInfoAccessIssuers',
    }],
  }],
}

function decodeExtAuthorityInfoAccess (e: Extension) {
  const captures = ASN1.parseDERWithTemplate(e.value, authorityInfoAccessValidator)
  if (captures.authorityInfoAccessOcsp != null) {
    e.authorityInfoAccessOcsp = captures.authorityInfoAccessOcsp.bytes.toString()
  }
  if (captures.authorityInfoAccessIssuers != null) {
    e.authorityInfoAccessIssuers = captures.authorityInfoAccessIssuers.bytes.toString()
  }
}

// Fills in missing fields in attributes.
function fillMissingFields (attrs: Attribute[]) {
  for (const attr of attrs) {
    // populate missing name
    if (attr.name == null || attr.name === '') {
      if (attr.oid != null) {
        attr.name = getOIDName(attr.oid)
      }
      if (attr.name === '' && attr.shortName != null) {
        attr.name = getOIDName(shortNames[attr.shortName])
      }
    }

    // populate missing type (OID)
    if (attr.oid == null || attr.oid === '') {
      if (attr.name !== '') {
        attr.oid = getOID(attr.name)
      } else {
        throw new Error('Attribute oid not specified.')
      }
    }

    // populate missing shortname
    if (attr.shortName == null || attr.shortName === '') {
      attr.shortName = shortNames[attr.name] == null ? '' : shortNames[attr.name]
    }

    if (attr.value == null) {
      throw new Error('Attribute value not specified.')
    }
  }
}

// Only support RSA and ECDSA
function getHashAgl (oid: string): string {
  switch (getOIDName(oid)) {
  case 'sha1WithRsaEncryption':
    return 'sha1'
  case 'md5WithRsaEncryption':
    return 'md5'
  case 'sha256WithRsaEncryption':
    return'sha256'
  case 'sha384WithRsaEncryption':
    return 'sha384'
  case 'sha512WithRsaEncryption':
    return 'sha512'
  case 'RSASSA-PSS':
    return'sha256'
  case 'ecdsaWithSha1':
    return'sha1'
  case 'ecdsaWithSha256':
    return'sha256'
  case 'ecdsaWithSha384':
    return'sha384'
  case 'ecdsaWithSha512':
    return'sha512'
  case 'dsaWithSha1':
    return'sha1'
  case 'dsaWithSha256':
    return'sha256'
  default:
    return ''
  }
}

// Converts an RDNSequence of ASN.1 DER-encoded RelativeDistinguishedName
// sets into an array with objects that have type and value properties.
function RDNAttributesAsArray (rdn: ASN1): Attribute[] {
  const rval = []

  // each value in 'rdn' in is a SET of RelativeDistinguishedName
  // var set, attr, obj
  for (const set of rdn.mustCompound()) {
    // each value in the SET is an AttributeTypeAndValue sequence
    // containing first a type (an OID) and second a value (defined by the OID)
    for (const attr of set.mustCompound()) {
      const values = attr.mustCompound()
      const obj = {} as Attribute
      obj.oid = ASN1.parseOID(values[0].bytes)
      obj.value = values[1].value
      obj.valueTag = values[1].tag
      obj.name = getOIDName(obj.oid)
      obj.shortName = getShortName(obj.name)

      rval.push(obj)
    }
  }

  return rval
}

function toJSONify (val: any): any {
  if (val != null && !(val instanceof Buffer) && typeof val.toJSON === 'function') {
    return val.toJSON()
  }
  return val
}
