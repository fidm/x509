'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { createHash, Hash } from 'crypto'
import { bytesToIP, bytesFromIP, getOID, getOIDName } from './common'
import { ASN1, Class, Tag, Template, Captures, BitString } from './asn1'
import { PEM } from './pem'

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

export interface Hasher {
  update (data: Buffer | string, inputEncoding?: string): any
  digest (encoding?: string): string | Buffer
}

export interface RSAPublicKey {
  n: string // modulus, hex string
  e: string // public exponent, hex string
}

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
const publicKeyValidator: Template = {
  name: 'SubjectPublicKeyInfo',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  capture: 'subjectPublicKeyInfo',
  value: [{
    name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
      capture: 'publicKeyOID',
    }],
  }, {
    name: 'SubjectPublicKeyInfo.subjectPublicKey',
    class: Class.UNIVERSAL,
    tag: Tag.BITSTRING,
    value: {
      name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
      class: Class.UNIVERSAL,
      tag: Tag.SEQUENCE,
      optional: true,
      capture: 'rsaPublicKey',
    },
  }],
}

// validator for an RSA public key
const rsaPublicKeyValidator: Template = {
  // RSAPublicKey
  name: 'RSAPublicKey',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    // modulus (n)
    name: 'RSAPublicKey.modulus',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'publicKeyModulus',
  }, {
    // publicExponent (e)
    name: 'RSAPublicKey.exponent',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'publicKeyExponent',
  }],
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
        tag: Tag.OCTETSTRING, // ?
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

// Converts an RSA public key from PEM format.
export function publicKeyFromPem (pem: Buffer): RSAPublicKey {
  const msg = PEM.parse(pem)[0]

  if (msg.type !== 'PUBLIC KEY' && msg.type !== 'RSA PUBLIC KEY') {
    throw new Error('Could not convert public key from PEM')
  }
  if (msg.procType.includes('ENCRYPTED')) {
    throw new Error('Could not convert public key from PEM; PEM is encrypted.');
  }

  return publicKeyFromASN1(ASN1.fromDER(msg.body))
}

// Converts an RSA public key to PEM format (using a SubjectPublicKeyInfo).
export function publicKeyToPem (key: RSAPublicKey): PEM {
  return new PEM('PUBLIC KEY', publicKeyToASN1(key).toDER())
}

// Converts an RSA public key to PEM format (using an RSAPublicKey).
export function publicKeyToRSAPublicKeyPem (key: RSAPublicKey): PEM {
  return new PEM('RSA PUBLIC KEY', publicKeyToRSAPublicKey(key).toDER())
}

export class TargetInfo {
  attributes: Attribute[]
  uniqueId: BitString | null
  constructor () {
    this.attributes = []
    this.uniqueId = null
  }

  getHash (): Buffer {
    const hasher = createHash('sha1')
    for (const attr of this.attributes) {
      hasher.update(attr.oid)
      hasher.update(attr.value)
    }
    return hasher.digest()
  }

  getField (sn: string): Attribute | null {
    return getAttribute(this, sn)
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
      let key = attr.shortName
      if (key == null || key === '') {
        key = attr.name
      }
      if (key == null || key === '') {
        key = attr.oid
      }
      obj[key] = attr.value
    }
    return obj
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
    return Certificate.fromASN1(obj)
  }

  // Converts an X.509v3 RSA certificate from an ASN.1 object.
  static fromASN1 (obj: ASN1): Certificate {
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
    const cert = new Certificate()
    cert.version = captures.certVersion == null ? 0 : ASN1.parseIntegerNum(captures.certVersion.bytes)
    cert.serialNumber = ASN1.parseIntegerStr(captures.certSerialNumber.bytes)
    cert.signatureOID = ASN1.parseOID(captures.certSignatureOID.bytes)
    if (captures.certSignatureParams != null) {
      cert.signatureParameters = readSignatureParameters(cert.signatureOID, captures.certSignatureParams, true)
    }
    cert.siginfo.algorithmOID = ASN1.parseOID(captures.certinfoSignatureOID.bytes)
    if (captures.certinfoSignatureParams != null) {
      cert.siginfo.parameters =
        readSignatureParameters(cert.siginfo.algorithmOID, captures.certinfoSignatureParams, false);
    }
    cert.signature = ASN1.parseBitString(captures.certSignature.bytes).buf

    if (captures.certValidity1UTCTime != null) {
      cert.validity.notBefore = ASN1.parseUTCTime(captures.certValidity1UTCTime.bytes)
    } else if (captures.certValidity2GeneralizedTime != null) {
      cert.validity.notBefore = ASN1.parseGeneralizedTime(captures.certValidity2GeneralizedTime.bytes)
    } else {
      throw new Error('Cannot read notBefore validity times')
    }

    if (captures.certValidity3UTCTime != null) {
      cert.validity.notAfter = ASN1.parseUTCTime(captures.certValidity3UTCTime.bytes)
    } else if (captures.certValidity4GeneralizedTime != null) {
      cert.validity.notAfter = ASN1.parseGeneralizedTime(captures.certValidity4GeneralizedTime.bytes)
    } else {
      throw new Error('Cannot read notAfter validity times')
    }
    // keep TBSCertificate to preserve signature when exporting
    cert.tbsCertificate = captures.tbsCertificate

    // handle issuer, build issuer message digest
    cert.issuer.setAttrs(RDNAttributesAsArray(captures.certIssuer))
    if (captures.certIssuerUniqueId != null) {
      cert.issuer.uniqueId = ASN1.parseBitString(captures.certIssuerUniqueId.bytes)
    }

    // handle subject, build subject message digest
    cert.subject.setAttrs(RDNAttributesAsArray(captures.certSubject))
    if (captures.certSubjectUniqueId != null) {
      cert.subject.uniqueId = ASN1.parseBitString(captures.certSubjectUniqueId.bytes)
    }

    // handle extensions
    if (captures.certExtensions != null) {
      cert.extensions = certificateExtensionsFromAsn1(captures.certExtensions)
    }

    // convert RSA public key from ASN.1
    cert.publicKey = publicKeyFromASN1(captures.subjectPublicKeyInfo)
    return cert
  }

  version: number
  serialNumber: string
  signatureOID: string
  signature: Buffer | null
  siginfo: any
  validity: { notBefore: Date, notAfter: Date }
  issuer: TargetInfo
  subject: TargetInfo
  extensions: Extension[]
  publicKey: RSAPublicKey | null
  signatureParameters: any
  tbsCertificate: ASN1 | null
  constructor () {
    this.version = 0x02
    this.serialNumber = '00'
    this.signatureOID = ''
    this.signature = null
    this.siginfo = {}
    this.siginfo.algorithmOID = null
    this.validity = { notBefore: new Date(), notAfter: new Date() }

    this.issuer = new TargetInfo()
    this.subject = new TargetInfo()
    this.extensions = []
    this.publicKey = null
    this.signatureParameters = {}
    this.tbsCertificate = null
  }

  toJSON () {
    return {
      version: this.version,
      serialNumber: this.serialNumber,
      signatureOID: this.signatureOID,
      signature: this.signature,
      siginfo: this.siginfo,
      validity: this.validity,
      issuer: this.issuer.toJSON(),
      subject: this.subject.toJSON(),
      extensions: this.extensions,
      publicKey: this.publicKey,
      signatureParameters: this.signatureParameters,
    }
  }

  // Sets the extensions of this certificate.
  setExtensions (exts: any) {
    for (const ext of exts) {
      fillMissingExtensionFields(ext, { cert: this })
    }
    // set new extensions
    this.extensions = exts
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

  getHash (): Buffer {
    const hasher = getHasher(this.signatureOID)
    if (hasher != null && this.tbsCertificate != null) {
      return hasher.update(this.tbsCertificate.bytes).digest()
    }
    throw new Error('Could not compute certificate digest.')
  }

  // Signs this certificate using the given private key.
  // sign (key: Buffer, alg: string) {
  //   // TODO: get signature OID from private key
  //   const algorithmOID = getOID(alg + 'WithRSAEncryption')
  //   const hasher = getHasher(algorithmOID)
  //   if(hasher == null) {
  //     throw new Error('Could not compute certificate digest: Unknown message digest algorithm OID.')
  //   }
  //   this.signatureOID = this.siginfo.algorithmOID = algorithmOID
  //   this.tbsCertificate = getTBSCertificate(this)

  //   // digest and sign
  //   hasher.update(this.tbsCertificate.bytes)
  //   // this.signature = key.sign(cert.md)
  // }

  // // Attempts verify the signature on the passed certificate using this certificate's public key.
  // verify (child: Certificate): boolean {
  //   if (!this.issued(child)) {
  //     throw new Error('The parent certificate did not issue the given child')
  //   }
  //   return false // TODO
  // }

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
  generateSubjectKeyIdentifier () {
    /* See: 4.2.1.2 section of the the RFC3280, keyIdentifier is either:

      (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
        value of the BIT STRING subjectPublicKey (excluding the tag,
        length, and number of unused bits).

      (2) The keyIdentifier is composed of a four bit type field with
        the value 0100 followed by the least significant 60 bits of the
        SHA-1 hash of the value of the BIT STRING subjectPublicKey
        (excluding the tag, length, and number of unused bit string bits).
    */

    // skipping the tag, length, and number of unused bits is the same
    // as just using the RSAPublicKey (for RSA keys, which are the
    // only ones supported)
    return getPublicKeyFingerprint(this.publicKey, { type: 'RSAPublicKey' })
  }

  // Verifies the subjectKeyIdentifier extension value for this certificate
  // against its public key. If no extension is found, false will be
  // returned.
  verifySubjectKeyIdentifier () {
    const oid = getOID('subjectKeyIdentifier')
    for (const ext of this.extensions) {
      if (ext.id === oid) {
        const ski = this.generateSubjectKeyIdentifier()
        return ski.equals(ext.subjectKeyIdentifier)
      }
    }
    return false
  }

  toASN1 (): ASN1 {
    if (this.tbsCertificate == null) {
      this.tbsCertificate = getTBSCertificate(this)
    }
    // Certificate
    return ASN1.Seq([
      // TBSCertificate
      this.tbsCertificate as ASN1,
      // AlgorithmIdentifier (signature algorithm)
      ASN1.Seq([
        // algorithm
        ASN1.OID(this.signatureOID),
        // parameters
        signatureParametersToASN1(this.signatureOID, this.signatureParameters),
      ]),
      // SignatureValue
      ASN1.BitString(this.signature as Buffer),
    ])
  }

  // Converts an X.509 certificate to PEM format.
  toPem () {
    return new PEM('CERTIFICATE', this.toASN1().toDER())
  }
}

export interface Extension {
  id: string
  critical: boolean
  value: Buffer
  name: string
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
    try {
      decodeExtBasicConstraints(e)
    } catch (_e) {
      // console.log(1111, _e)
    }
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
    // value is an OCTETSTRING w/the hash of the key-type specific
    // public key structure (eg: RSAPublicKey)
    e.subjectKeyIdentifier = e.value.toString('hex')
    break
  case 'authorityKeyIdentifier':
    e.authorityKeyIdentifier = e.value.toString('hex')
    break
  }
  return e
}

function decodeExtKeyUsage (e: Extension) {
  // get value as OCTETSTRING
  const ev = ASN1.parseBitString(e.value)
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

function encodeExtKeyUsage (e: Extension) {
  // build flags
  let unused = 0
  let b2 = 0x00
  let b3 = 0x00
  if (e.digitalSignature === true) {
    b2 |= 0x80
    unused = 7
  }
  if (e.nonRepudiation === true) {
    b2 |= 0x40
    unused = 6
  }
  if (e.keyEncipherment === true) {
    b2 |= 0x20
    unused = 5
  }
  if (e.dataEncipherment === true) {
    b2 |= 0x10
    unused = 4
  }
  if (e.keyAgreement === true) {
    b2 |= 0x08
    unused = 3
  }
  if (e.keyCertSign === true) {
    b2 |= 0x04
    unused = 2
  }
  if (e.cRLSign === true) {
    b2 |= 0x02
    unused = 1
  }
  if (e.encipherOnly === true) {
    b2 |= 0x01
    unused = 0
  }
  if (e.decipherOnly === true) {
    b3 |= 0x80
    unused = 7
  }

  // create bit string
  const vals = []
  if (b3 !== 0) {
    vals.push(b2, b3)
  } else if (b2 !== 0) {
    vals.push(b2)
  }
  e.value = ASN1.BitString(new BitString(Buffer.from(vals), vals.length * 8 - unused)).toDER()
}

function decodeExtBasicConstraints (e: Extension) {
  // handle basic constraints
  // get value as SEQUENCE
  const ev = ASN1.fromDER(e.value)
  const vals = ev.mustCompound()
  // get cA BOOLEAN flag (defaults to false)
  if (vals.length > 0 && vals[0].tag === Tag.BOOLEAN) {
    e.cA = ASN1.parseBool(vals[0].bytes)
  } else {
    e.cA = false
  }
  // get path length constraint
  let value = null
  if (vals.length > 0 && vals[0].tag === Tag.INTEGER) {
    value = vals[0].bytes
  } else if (vals.length > 1) {
    value = vals[1].bytes
  }

  if (value !== null) {
    e.pathLenConstraint = ASN1.parseInteger(value)
  }
}

function encodeExtBasicConstraints (e: Extension) {
  // basicConstraints is a SEQUENCE
  const vals: ASN1[] = []
  // cA BOOLEAN flag defaults to false
  if (e.cA === true) {
    vals.push(ASN1.Bool(true))
  }

  if (e.pathLenConstraint != null) {
    vals.push(ASN1.Integer(e.pathLenConstraint))
  }
  e.value = ASN1.Seq(vals).toDER()
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

function encodeExtExtKeyUsage (e: Extension) {
  // extKeyUsage is a SEQUENCE of OIDs
  const vals: ASN1[] = []

  for (const key of Object.keys(e)) {
    if (e[key] !== true) {
      continue
    }
    const oid = getOID(key)
    if (oid !== '') {
      vals.push(ASN1.OID(oid))
    }
  }
  e.value = ASN1.Seq(vals).toDER()
}

function decodeExtNsCertType (e: Extension) {
  // handle nsCertType
  // get value as OCTETSTRING
  const ev = ASN1.parseBitString(e.value)
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

function encodeExtNsCertType (e: Extension) {
  // nsCertType is a OCTETSTRING
  // build flags
  let unused = 0
  let b2 = 0x00

  if (e.client === true) {
    b2 |= 0x80
    unused = 7
  }
  if (e.server === true) {
    b2 |= 0x40
    unused = 6
  }
  if (e.email === true) {
    b2 |= 0x20
    unused = 5
  }
  if (e.objsign === true) {
    b2 |= 0x10
    unused = 4
  }
  if (e.reserved === true) {
    b2 |= 0x08
    unused = 3
  }
  if (e.sslCA === true) {
    b2 |= 0x04
    unused = 2
  }
  if (e.emailCA === true) {
    b2 |= 0x02
    unused = 1
  }
  if (e.objCA === true) {
    b2 |= 0x01
    unused = 0
  }

  // create bit string
  const vals = []
  if (b2 !== 0) {
    vals.push(b2)
  }
  e.value = ASN1.BitString(new BitString(Buffer.from(vals), vals.length * 8 - unused)).toDER()
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

    // Note: Support for types 1,2,6,7,8
    switch (gn.tag) {
    // rfc822Name
    case 1:
    // dNSName
    case 2:
    // uniformResourceIdentifier (URI)
    case 6:
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

function encodeExtAltName (e: Extension) {
  const vals: ASN1[] = []

  for (const altName of e.altNames) {
    let bytes = altName.value
    // handle IP
    if (altName.tag === 7 && altName.ip != null) {
      bytes = bytesFromIP(altName.ip)
      if (bytes == null) {
        throw new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.')
      }
    } else if (altName.tag === 8) {
      // handle OID
      if (altName.oid != null) {
        bytes = ASN1.OID(altName.oid).toDER()
      }
    }
    vals.push(ASN1.Spec(altName.tag as Tag, bytes, false))
  }
  e.value = ASN1.Seq(vals).toDER()
}

function encodeExtSubjectKeyIdentifier (e: Extension, cert: Certificate) {
  if (cert == null) {
    return
  }
  const ski = cert.generateSubjectKeyIdentifier()
  e.subjectKeyIdentifier = ski.toString('hex')
  e.value = new ASN1(Class.UNIVERSAL, Tag.OCTETSTRING, ski).toDER()
}

function encodeExtAuthorityKeyIdentifier (e: Extension, cert: Certificate) {
  if (cert == null) {
    return
  }
  // SYNTAX SEQUENCE
  const vals: ASN1[] = []

  if (e.keyIdentifier != null) {
    const keyIdentifier = e.keyIdentifier === true ? cert.generateSubjectKeyIdentifier() : e.keyIdentifier
    vals.push(ASN1.Spec(0 as Tag, keyIdentifier, false))
  }

  if (e.authorityCertIssuer != null) {
    const authorityCertIssuer = [
      ASN1.Spec(4 as Tag, [
        dnToASN1(e.authorityCertIssuer === true ? cert.issuer : e.authorityCertIssuer),
      ]),
    ]
    vals.push(ASN1.Spec(1 as Tag, authorityCertIssuer))
  }

  if (e.serialNumber != null) {
    const serialNumber = e.serialNumber === true ? cert.serialNumber : e.serialNumber
    vals.push(ASN1.Spec(2 as Tag, serialNumber, false))
  }
  e.value = ASN1.Seq(vals).toDER()
}

function encodeExtCRLDistributionPoints (e: Extension) {
  // Create fullName CHOICE
  const fullNameGeneralNames: ASN1[] = []
  for (const altName of e.altNames) {
    let value = altName.value
    // handle IP
    if (altName.tag === 7 && altName.ip != null) {
      value = bytesFromIP(altName.ip)
      if (value === null) {
        throw new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.')
      }
    } else if (altName.tag === 8) {
      // handle OID
      if (altName.oid != null) {
        value = ASN1.OID(altName.oid).toDER()
      }
    }

    fullNameGeneralNames.push(ASN1.Spec(altName.tag as Tag, value, false))
  }

  // Add to the parent SEQUENCE
  e.value = ASN1.Seq([
    // Create sub SEQUENCE of DistributionPointName
    ASN1.Seq([
      ASN1.Spec(0 as Tag, [
        ASN1.Spec(0 as Tag, fullNameGeneralNames),
      ]),
    ]),
  ]).toDER()
}

// Fills in missing fields in certificate extensions.
function fillMissingExtensionFields (e: Extension, options: any = {}): Extension {
  // populate missing name
  if (e.name == null) {
    e.name = getOIDName(e.id)
  }

  // populate missing id
  if (e.id == null || e.id === '') {
    e.id = getOID(e.name)
  }

  if (e.id === '') {
    throw new Error('Extension ID not specified.')
  }

  if (e.value == null) {
    return e
  }

  // handle missing value:
  switch (e.name) {
  case 'keyUsage':
    encodeExtKeyUsage(e)
    break
  case 'basicConstraints':
    encodeExtBasicConstraints(e)
    break
  case 'extKeyUsage':
    encodeExtExtKeyUsage(e)
    break
  case 'nsCertType':
    encodeExtNsCertType(e)
    break
  case 'subjectAltName':
    encodeExtAltName(e)
    break
  case 'issuerAltName':
    encodeExtAltName(e)
    break
  case 'subjectKeyIdentifier':
    encodeExtSubjectKeyIdentifier(e, options.cert)
    break
  case 'authorityKeyIdentifier':
    encodeExtAuthorityKeyIdentifier(e, options.cert)
    break
  case 'cRLDistributionPoints':
    encodeExtCRLDistributionPoints(e)
    break
  }

  // ensure value has been defined by now
  if (e.value == null) {
    throw new Error('Extension value not specified.')
  }

  return e
}

function dnToASN1 (obj: TargetInfo): ASN1 {
  // iterate over attributes
  const vals: ASN1[] = []
  for (const attr of obj.attributes) {
    let value = attr.value
    // reuse tag class for attribute value if available
    let valueTag = Tag.PRINTABLESTRING
    if (attr.valueTag != null) {
      valueTag = attr.valueTag
    }
    if (valueTag === Tag.UTF8) {
      value = Buffer.from(value, 'utf8')
    }
    // TODO: handle more encodings

    // create a RelativeDistinguishedName set
    // each value in the set is an AttributeTypeAndValue first
    // containing the type (an OID) and second the value
    vals.push(ASN1.Set([
      ASN1.Seq([
        // AttributeType
        ASN1.OID(attr.oid),
        // AttributeValue
        new ASN1(Class.UNIVERSAL, valueTag, value),
      ]),
    ]))
  }

  return ASN1.Seq(vals)
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

    // convert extensions to value
    if (attr.oid === getOID('extensionRequest')) {
      // attr.valueConstructed = true
      attr.valueTag = Tag.SEQUENCE
      if (attr.value == null && attr.extensions) {
        attr.value = []
        for (const ext of attr.extensions) {
          attr.value.push(certificateExtensionToASN1(fillMissingExtensionFields(ext)))
        }
      }
    }

    if (attr.value == null) {
      throw new Error('Attribute value not specified.')
    }
  }
}

function signatureParametersToASN1 (oid: string, params: any): ASN1 {
  switch (oid) {
  case getOID('RSASSA-PSS'):
    const parts: ASN1[] = []

    if (params.hash.algorithmOID != null) {
      parts.push(ASN1.Spec(0 as Tag, ASN1.Seq([
        ASN1.OID(params.hash.algorithmOID),
        ASN1.Null(),
      ])))
    }

    if (params.mgf.algorithmOID != null) {
      parts.push(ASN1.Spec(1 as Tag, ASN1.Seq([
        ASN1.Seq([
          ASN1.OID(params.mgf.algorithmOID),
          ASN1.Seq([
            ASN1.OID(params.mgf.hash.algorithmOID),
            ASN1.Null(),
          ]),
        ]),
      ])))
    }

    if (params.saltLength != null) {
      parts.push(ASN1.Spec(2 as Tag, ASN1.Integer(params.saltLength)))
    }

    return ASN1.Seq(parts)
  default:
    return ASN1.Null()
  }
}

// Gets the ASN.1 TBSCertificate part of an X.509v3 certificate.
function getTBSCertificate (cert: Certificate): ASN1 {
  // TBSCertificate
  const tbs: ASN1[] = [
    // version
    ASN1.Spec(0 as Tag, ASN1.Integer(cert.version)),
    // serialNumber
    ASN1.Integer(Buffer.from(cert.serialNumber, 'hex')),
    // signature
    ASN1.Seq([
      // algorithm
      ASN1.OID(cert.siginfo.algorithmOID),
      // parameters
      signatureParametersToASN1(cert.siginfo.algorithmOID, cert.siginfo.parameters),
    ]),
    // issuer
    dnToASN1(cert.issuer),
    // validity
    ASN1.Seq([
      // notBefore
      ASN1.UTCTime(cert.validity.notBefore),
      // notAfter
      ASN1.UTCTime(cert.validity.notAfter),
    ]),
    // subject
    dnToASN1(cert.subject),
    // SubjectPublicKeyInfo
    publicKeyToASN1(cert.publicKey as RSAPublicKey),
  ]

  if (cert.issuer.uniqueId != null) {
    // issuerUniqueID (optional)
    tbs.push(ASN1.Spec(1 as Tag, ASN1.BitString(cert.issuer.uniqueId)))
  }

  if (cert.subject.uniqueId != null) {
    // subjectUniqueID (optional)
    tbs.push(ASN1.Spec(2 as Tag, ASN1.BitString(cert.subject.uniqueId)))
  }

  if (cert.extensions.length > 0) {
    // extensions (optional)
    tbs.push(certificateExtensionsToASN1(cert.extensions))
  }

  return ASN1.Seq(tbs)
}

// Converts X.509v3 certificate extensions to ASN.1.
function certificateExtensionsToASN1 (exts: Extension[]): ASN1 {
  const seq = ASN1.Seq(exts.map(certificateExtensionToASN1))
  return ASN1.Spec(3 as Tag, seq)
}

// Converts a single certificate extension to ASN.1.
function certificateExtensionToASN1 (ext: Extension): ASN1 {

  const vals: ASN1[] = []
  // extnID (OID)
  vals.push(ASN1.OID(ext.id))
  // critical defaults to false
  if (ext.critical) {
    vals.push(ASN1.Bool(true))
  }
  // extnValue (OCTET STRING)
  vals.push(new ASN1(Class.UNIVERSAL, Tag.OCTETSTRING, ext.value))

  return ASN1.Seq(vals)
}

function getHasher (oid: string): Hash | null {
  let algorithm = ''
  switch (getOIDName(oid)) {
  case 'sha1WithRSAEncryption':
    algorithm = 'sha1'
    break
  case 'md5WithRSAEncryption':
    algorithm = 'md5'
    break
  case 'sha256WithRSAEncryption':
    algorithm = 'sha256'
    break
  case 'sha384WithRSAEncryption':
    algorithm = 'sha384'
    break
  case 'sha512WithRSAEncryption':
    algorithm = 'sha512'
    break
  case 'RSASSA-PSS':
    algorithm = 'sha256'
    break
  }

  return algorithm !== '' ? createHash(algorithm) : null
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

// Gets an issuer or subject attribute from its name, type, or short name.
function getAttribute (obj: { attributes: Attribute[] }, key: any): Attribute | null {
  for (const attr of obj.attributes) {
    if (key === attr.oid || key === attr.name || key === attr.shortName) {
      return attr
    }
  }
  return null
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
    params.hash = params.hash || {}
    params.hash.algorithmOID = ASN1.parseOID(capture.hashOID.bytes)
  }

  if (capture.maskGenOID != null) {
    params.mgf = params.mgf || {}
    params.mgf.algorithmOID = ASN1.parseOID(capture.maskGenOID.bytes)
    params.mgf.hash = params.mgf.hash || {}
    params.mgf.hash.algorithmOID = ASN1.parseOID(capture.maskGenHashOID.bytes)
  }

  if (capture.saltLength != null) {
    params.saltLength = ASN1.parseInteger(capture.saltLength.bytes)
  }

  return params
}

function getPublicKeyFingerprint (key: any, options: any): Buffer {
  options = options || {}
  const md = options.md // || forge.md.sha1.create();
  const type = options.type || 'RSAPublicKey';

  let bytes
  switch (type) {
  case 'RSAPublicKey':
    bytes = publicKeyToRSAPublicKey(key).toDER()
    break;
  case 'SubjectPublicKeyInfo':
    bytes = publicKeyToASN1(key).toDER()
    break;
  default:
    throw new Error('Unknown fingerprint type "' + options.type + '".')
  }

  // hash public key bytes
  md.start()
  md.update(bytes)
  return md.digest()
}

function publicKeyToRSAPublicKey (key: RSAPublicKey): ASN1 {
  // RSAPublicKey
  return ASN1.Seq([
    // modulus (n)
    ASN1.Integer(Buffer.from(key.n, 'hex')),
    // publicExponent (e)
    ASN1.Integer(Buffer.from(key.e, 'hex')),
  ])
}

function publicKeyToASN1 (key: RSAPublicKey): ASN1 {
  // SubjectPublicKeyInfo
  return ASN1.Seq([
    // AlgorithmIdentifier
    ASN1.Seq([
      // algorithm
      ASN1.OID(getOID('rsaEncryption')),
      // parameters (null)
      ASN1.Null(),
    ]),
    // subjectPublicKey
    ASN1.BitString(publicKeyToRSAPublicKey(key).toDER()),
  ])
}

function publicKeyFromASN1 (obj: ASN1): RSAPublicKey {
  // get SubjectPublicKeyInfo
  const captures: Captures = Object.create(null)
  let err = obj.validate(publicKeyValidator, captures)
  if (err != null) {
    throw new Error('Cannot read X.509 public key: ' + err.message)
  }

  const oid = ASN1.parseOID(captures.publicKeyOID.bytes)
  if (oid !== getOID('rsaEncryption')) {
    throw new Error('Cannot read public key. Unknown OID.')
  }

  // get RSA params
  err = captures.rsaPublicKey.validate(rsaPublicKeyValidator, captures)
  if (err != null) {
    throw new Error('Cannot read X.509 public key: ' + err.message)
  }

  return {
    n: captures.publicKeyModulus.bytes.toString('hex'),
    e: captures.publicKeyExponent.bytes.toString('hex'),
  }
}
