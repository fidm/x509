'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { inspect } from 'util'
import { createHash, Hash } from 'crypto'
import { bytesToIP, getOID, getOIDName } from './common'
import { ASN1, Class, Tag, Template, Captures, BitString } from './asn1'
import { PEM } from './pem'
import { publicKeyValidator, RSAPublicKey } from './rsa'

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
      // Note: UTC and generalized times may both appear so the capture
      // names are based on their detected order, the names used below
      // are only for the common case, which validity time really means
      // "notBefore" and which means "notAfter" will be determined by order
      value: [{
        // notBefore (Time) (UTC time case)
        name: 'Certificate.TBSCertificate.validity.notBefore (utc)',
        class: Class.UNIVERSAL,
        tag: Tag.UTCTIME,
        optional: true,
        capture: 'certValidity1UTCTime',
      }, {
        // notBefore (Time) (generalized time case)
        name: 'Certificate.TBSCertificate.validity.notBefore (generalized)',
        class: Class.UNIVERSAL,
        tag: Tag.GENERALIZEDTIME,
        optional: true,
        capture: 'certValidity2GeneralizedTime',
      }, {
        // notAfter (Time) (only UTC time is supported)
        name: 'Certificate.TBSCertificate.validity.notAfter (utc)',
        class: Class.UNIVERSAL,
        tag: Tag.UTCTIME,
        optional: true,
        capture: 'certValidity3UTCTime',
      }, {
        // notAfter (Time) (only UTC time is supported)
        name: 'Certificate.TBSCertificate.validity.notAfter (generalized)',
        class: Class.UNIVERSAL,
        tag: Tag.GENERALIZEDTIME,
        optional: true,
        capture: 'certValidity4GeneralizedTime',
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
      tag: Tag.OCTETSTRING, // ?
      optional: true,
      capture: 'certSignatureParams',
    }],
  }, {
    // SignatureValue
    name: 'Certificate.signatureValue',
    class: Class.UNIVERSAL,
    tag: Tag.BITSTRING,
    capture: 'certSignature',
  }],
}

const rsassaPssParameterValidator: Template = {
  name: 'rsapss',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    name: 'rsapss.hashAlgorithm',
    class: Class.CONTEXT_SPECIFIC,
    tag: Tag.NONE,
    value: [{
      name: 'rsapss.hashAlgorithm.AlgorithmIdentifier',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      optional: true,
      value: [{
        name: 'rsapss.hashAlgorithm.AlgorithmIdentifier.algorithm',
        class: Class.UNIVERSAL,
        tag: Tag.OID,
        capture: 'hashOID',
        /* parameter block omitted, for SHA1 NULL anyhow. */
      }],
    }],
  }, {
    name: 'rsapss.maskGenAlgorithm',
    class: Class.CONTEXT_SPECIFIC,
    tag: Tag.BOOLEAN,
    value: [{
      name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      optional: true,
      value: [{
        name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.algorithm',
        class: Class.UNIVERSAL,
        tag: Tag.OID,
        capture: 'maskGenOID',
      }, {
        name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params',
        class: Class.UNIVERSAL,
        tag: Tag.SEQUENCE,
        value: [{
          name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params.algorithm',
          class: Class.UNIVERSAL,
          tag: Tag.OID,
          capture: 'maskGenHashOID',
          /* parameter block omitted, for SHA1 NULL anyhow. */
        }],
      }],
    }],
  }, {
    name: 'rsapss.saltLength',
    class: Class.CONTEXT_SPECIFIC,
    tag: Tag.INTEGER,
    optional: true,
    value: [{
      name: 'rsapss.saltLength.saltLength',
      class: Class.UNIVERSAL,
      tag: Tag.INTEGER,
      capture: 'saltLength',
    }],
  }, {
    name: 'rsapss.trailerField',
    class: Class.CONTEXT_SPECIFIC,
    tag: Tag.BITSTRING,
    optional: true,
    value: [{
      name: 'rsapss.trailer.trailer',
      class: Class.UNIVERSAL,
      tag: Tag.INTEGER,
      capture: 'trailer',
    }],
  }],
}

export interface Attribute {
  oid: string,
  value: any,
  valueTag: Tag,
  name: string,
  shortName: string,
  extensions?: Extension[]
}

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

// Creates an empty X.509v3 RSA certificate.
export class Certificate {
  // Converts an X.509 certificate from PEM format.
  static fromPEM (pem: Buffer): Certificate {
    const msg = PEM.parse(pem)[0]

    if (msg.type !== 'CERTIFICATE' &&
      msg.type !== 'X509 CERTIFICATE' &&
      msg.type !== 'TRUSTED CERTIFICATE') {
      throw new Error('Could not convert certificate from PEM: invalid type')
    }
    if (msg.procType.includes('ENCRYPTED')) {
      throw new Error('Could not convert certificate from PEM; PEM is encrypted.')
    }

    const obj = ASN1.fromDER(msg.body)
    return new Certificate(obj)
  }

  readonly version: number
  readonly serialNumber: string
  readonly signatureOID: string
  readonly signatureAlgorithm: string
  readonly signatureParameters: any
  readonly siginfo: any
  readonly signature: Buffer
  readonly subjectKeyIdentifier: string
  readonly authorityKeyIdentifier: string
  readonly ocspServer: string
  readonly issuingCertificateURL: string
  readonly isCA: boolean
  readonly maxPathLen: number
  readonly basicConstraintsValid: boolean
  readonly dnsNames: string[]
  readonly emailAddresses: string[]
  readonly ipAddresses: string[]
  readonly uris: string[]
  readonly validFrom: Date
  readonly validTo: Date
  readonly issuer: DistinguishedName
  readonly subject: DistinguishedName
  readonly extensions: Extension[]
  readonly publicKey: RSAPublicKey
  readonly publicKeyRaw: Buffer
  readonly tbsCertificate: ASN1
  constructor (obj: ASN1) {
    // validate certificate and capture data
    const captures: Captures = Object.create(null)
    const err = obj.validate(x509CertificateValidator, captures)
    if (err != null) {
      throw new Error('Cannot read X.509 certificate: ' + err.message)
    }

    // get oid
    const oid = ASN1.parseOID(captures.publicKeyOID.bytes)
    if (oid !== getOID('rsaEncryption')) {
      throw new Error('Cannot read public key. OID is not RSA.')
    }

    // create certificate
    this.version = captures.certVersion == null ? 0 : ASN1.parseIntegerNum(captures.certVersion.bytes)
    this.serialNumber = ASN1.parseIntegerStr(captures.certSerialNumber.bytes)
    this.signatureOID = ASN1.parseOID(captures.certSignatureOID.bytes)
    this.signatureAlgorithm = getOIDName(this.signatureOID)
    this.signatureParameters = null
    if (captures.certSignatureParams != null) {
      this.signatureParameters = readSignatureParameters(this.signatureOID, captures.certSignatureParams, true)
    }

    this.siginfo = {}
    this.siginfo.algorithmOID = ASN1.parseOID(captures.certinfoSignatureOID.bytes)
    if (captures.certinfoSignatureParams != null) {
      this.siginfo.parameters =
        readSignatureParameters(this.siginfo.algorithmOID, captures.certinfoSignatureParams, false)
    }
    this.signature = ASN1.parseBitString(captures.certSignature.bytes).buf

    if (captures.certValidity1UTCTime != null) {
      this.validFrom = ASN1.parseUTCTime(captures.certValidity1UTCTime.bytes)
    } else if (captures.certValidity2GeneralizedTime != null) {
      this.validFrom = ASN1.parseGeneralizedTime(captures.certValidity2GeneralizedTime.bytes)
    } else {
      throw new Error('Cannot read notBefore validity times')
    }

    if (captures.certValidity3UTCTime != null) {
      this.validTo = ASN1.parseUTCTime(captures.certValidity3UTCTime.bytes)
    } else if (captures.certValidity4GeneralizedTime != null) {
      this.validTo = ASN1.parseGeneralizedTime(captures.certValidity4GeneralizedTime.bytes)
    } else {
      throw new Error('Cannot read notAfter validity times')
    }

    this.issuer = new DistinguishedName()
    this.issuer.setAttrs(RDNAttributesAsArray(captures.certIssuer))
    if (captures.certIssuerUniqueId != null) {
      this.issuer.uniqueId = ASN1.parseBitString(captures.certIssuerUniqueId.bytes)
    }

    this.subject = new DistinguishedName()
    this.subject.setAttrs(RDNAttributesAsArray(captures.certSubject))
    if (captures.certSubjectUniqueId != null) {
      this.subject.uniqueId = ASN1.parseBitString(captures.certSubjectUniqueId.bytes)
    }

    this.extensions = []
    this.subjectKeyIdentifier = ''
    this.authorityKeyIdentifier = ''
    this.ocspServer = ''
    this.issuingCertificateURL = ''
    this.isCA = false
    this.maxPathLen = -1
    this.basicConstraintsValid = false
    this.dnsNames = []
    this.emailAddresses = []
    this.ipAddresses = []
    this.uris = []
    if (captures.certExtensions != null) {
      this.extensions = certificateExtensionsFromAsn1(captures.certExtensions)
      for (const ext of this.extensions) {
        if (typeof ext.subjectKeyIdentifier === 'string') {
          this.subjectKeyIdentifier = ext.subjectKeyIdentifier
        }
        if (typeof ext.authorityKeyIdentifier === 'string') {
          this.authorityKeyIdentifier = ext.authorityKeyIdentifier
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

    // convert RSA public key from ASN.1
    this.publicKey = RSAPublicKey.fromPublicKeyASN1(captures.subjectPublicKeyInfo)
    this.publicKeyRaw = captures.subjectPublicKeyInfo.toDER()
    this.tbsCertificate = captures.tbsCertificate
  }

  toJSON () {
    const obj = {} as any
    for (const key of Object.keys(this)) {
      obj[key] = toJSONify((this as any)[key])
    }
    delete obj.tbsCertificate
    return obj
  }

  // Gets an extension by its name or id.
  getExtension (options: any) {
    if (typeof options === 'string') {
      options = { name: options }
    }

    for (const ext of this.extensions) {
      if ((options.id != null && ext.id === options.id) ||
        (options.name != null && ext.name === options.name)) {
        return ext
      }
    }
    return null
  }

  // Attempts verify the signature on the passed certificate using this certificate's public key.
  verify (child: Certificate): boolean {
    if (!this.issued(child)) {
      return false
    }

    const agl = getHashAgl(this.signatureOID)
    if (agl === '') {
      return false
    }

    return this.publicKey.verify(child.tbsCertificate.toDER(), child.signature, agl)
  }

  // Returns true if this certificate's issuer matches the passed
  // certificate's subject. Note that no signature check is performed.
  isIssuer (parent: Certificate) {
    return this.issuer.getHash().equals(parent.subject.getHash())
  }

  // Returns true if this certificate's subject matches the issuer of the
  // given certificate). Note that not signature check is performed.
  issued (child: Certificate) {
    return child.isIssuer(this)
  }

  // Generates the subjectKeyIdentifier for this certificate as byte buffer.
  generateSubjectKeyIdentifier (hasher?: Hash) {
    if (hasher == null) {
      hasher = createHash('sha1')
    }
    return this.publicKey.getFingerprint(hasher, 'RSAPublicKey')
  }

  // Verifies the subjectKeyIdentifier extension value for this certificate
  // against its public key. If no extension is found, false will be
  // returned.
  verifySubjectKeyIdentifier () {
    const ski = this.generateSubjectKeyIdentifier()
    return ski.toString('hex') === this.subjectKeyIdentifier
  }

  [inspect.custom] (_depth: any, options: any): string {
    if (options.depth <= 2) {
      options.depth = 10
    }
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

export interface Extension {
  id: string
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
  e.id = ASN1.parseOID(ext.value[0].bytes)
  e.critical = false

  if (ext.value[1].tag === Tag.BOOLEAN) {
    e.critical = ASN1.parseBool(ext.value[1].bytes)
    e.value = ext.value[2].bytes
  } else {
    e.value = ext.value[1].bytes
  }

  // if the oid is known, get its name
  e.name = getOIDName(e.id)
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
    const oid = ASN1.parseOID(val.bytes)
    const name = getOIDName(oid)
    e[name === '' ? oid : name] = true
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

function getHashAgl (oid: string): string {
  switch (getOIDName(oid)) {
  case 'sha1WithRSAEncryption':
    return 'sha1'
  case 'md5WithRSAEncryption':
    return 'md5'
  case 'sha256WithRSAEncryption':
    return'sha256'
  case 'sha384WithRSAEncryption':
    return 'sha384'
  case 'sha512WithRSAEncryption':
    return 'sha512'
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

function readSignatureParameters (oid: string, obj: ASN1, fillDefaults: boolean) {
  const params = {} as any

  if (oid !== getOID('RSASSA-PSS')) {
    return params
  }

  if (fillDefaults) {
    params.hash = { algorithmOID: getOID('sha1') }
    params.mgf = {
      algorithmOID: getOID('mgf1'),
      hash: { algorithmOID: getOID('sha1') },
    }
    params.saltLength = 20
  }

  const capture: Captures = Object.create(null)
  if (obj.validate(rsassaPssParameterValidator, capture) != null) {
    throw new Error('Cannot read RSASSA-PSS parameter block.')
  }

  if (capture.hashOID != null) {
    if (params.hash == null) {
      params.hash = {}
    }
    params.hash.algorithmOID = ASN1.parseOID(capture.hashOID.bytes)
  }

  if (capture.maskGenOID != null) {
    if (params.mgf == null) {
      params.mgf = {}
    }
    params.mgf.algorithmOID = ASN1.parseOID(capture.maskGenOID.bytes)
    if (params.mgf.hash == null) {
      params.mgf.hash = {}
    }
    params.mgf.hash.algorithmOID = ASN1.parseOID(capture.maskGenHashOID.bytes)
  }

  if (capture.saltLength != null) {
    params.saltLength = ASN1.parseInteger(capture.saltLength.bytes)
  }

  return params
}

function toJSONify (val: any): any {
  if (val != null && !(val instanceof Buffer) && typeof val.toJSON === 'function') {
    return val.toJSON()
  }
  return val
}
