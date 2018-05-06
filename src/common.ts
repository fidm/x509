'use strict'
// **Github:** https://github.com/fidm/x509js
//
// **License:** MIT

export class Visitor {
  start: number
  end: number
  constructor (start: number = 0, end: number = 0) {
    this.start = start
    this.end = end > start ? end : start
  }

  reset (start: number = 0, end: number = 0): this {
    this.start = start
    if (end >= this.start) {
      this.end = end
    } else if (this.end < this.start) {
      this.end = this.start
    }
    return this
  }

  walk (steps: number): this {
    this.start = this.end
    this.end += steps
    return this
  }
}

export class BufferVisitor extends Visitor {
  buf: Buffer
  constructor (buf: Buffer, start: number = 0, end: number = 0) {
    super(start, end)
    this.buf = buf
  }

  get length () {
    return this.buf.length
  }

  assertRemaining (steps: number, message?: string) {
    const requested = this.end + steps
    if (requested > this.buf.length) {
      const error = new Error(message == null ? 'Too few bytes to parse.' : message) as any
      error.available = this.buf.length
      error.requested = requested
      throw error
    }
    this.walk(0)
  }

  assertWalk (steps: number, message?: string) {
    this.assertRemaining(steps, message)
    this.walk(steps)
  }
}

export interface ToBuffer {
  byteLen (): number
  writeTo (bufv: BufferVisitor): BufferVisitor
}

export function toBuffer (obj: ToBuffer): Buffer {
  const bufv = obj.writeTo(new BufferVisitor(Buffer.alloc(obj.byteLen())))
  return bufv.buf
}

const oids = Object.create(null)
const oidReg = /^[0-9.]+$/

// getOID returns oid or ''
export function getOID (nameOrId: string): string {
  if (oidReg.test(nameOrId) && oids[nameOrId] !== '') {
    return nameOrId
  }
  return oids[nameOrId] || ''
}

// getOIDName return name or oid
export function getOIDName (nameOrId: string): string {
  if (!oidReg.test(nameOrId) && oids[nameOrId] !== '') {
    return nameOrId
  }
  return oids[nameOrId] || ''
}

// set id to name mapping and name to id mapping
function init (id: string, name: string, unidirection: boolean = false) {
  oids[id] = name

  if (!unidirection) {
    oids[name] = id
  }
}

// algorithm OIDs
init('1.2.840.113549.1.1.1', 'rsaEncryption')
// init('1.2.840.113549.1.1.2', 'md2WithRSAEncryption') not implemented
// init('1.2.840.113549.1.1.3', 'md4WithRSAEncryption') not implemented
init('1.2.840.113549.1.1.4', 'md5WithRSAEncryption')
init('1.2.840.113549.1.1.5', 'sha1WithRSAEncryption')
init('1.2.840.113549.1.1.7', 'RSAES-OAEP')
init('1.2.840.113549.1.1.8', 'mgf1')
init('1.2.840.113549.1.1.9', 'pSpecified')
init('1.2.840.113549.1.1.10', 'RSASSA-PSS')
init('1.2.840.113549.1.1.11', 'sha256WithRSAEncryption')
init('1.2.840.113549.1.1.12', 'sha384WithRSAEncryption')
init('1.2.840.113549.1.1.13', 'sha512WithRSAEncryption')
init('1.2.840.10040.4.3', 'dsa-with-sha1')
init('1.3.14.3.2.7', 'desCBC')
init('1.3.14.3.2.26', 'sha1')
init('2.16.840.1.101.3.4.2.1', 'sha256')
init('2.16.840.1.101.3.4.2.2', 'sha384')
init('2.16.840.1.101.3.4.2.3', 'sha512')
init('1.2.840.113549.2.5', 'md5')

// pkcs#7 content types
init('1.2.840.113549.1.7.1', 'data')
init('1.2.840.113549.1.7.2', 'signedData')
init('1.2.840.113549.1.7.3', 'envelopedData')
init('1.2.840.113549.1.7.4', 'signedAndEnvelopedData')
init('1.2.840.113549.1.7.5', 'digestedData')
init('1.2.840.113549.1.7.6', 'encryptedData')

// pkcs#9 oids
init('1.2.840.113549.1.9.1', 'emailAddress')
init('1.2.840.113549.1.9.2', 'unstructuredName')
init('1.2.840.113549.1.9.3', 'contentType')
init('1.2.840.113549.1.9.4', 'messageDigest')
init('1.2.840.113549.1.9.5', 'signingTime')
init('1.2.840.113549.1.9.6', 'counterSignature')
init('1.2.840.113549.1.9.7', 'challengePassword')
init('1.2.840.113549.1.9.8', 'unstructuredAddress')
init('1.2.840.113549.1.9.14', 'extensionRequest')
init('1.2.840.113549.1.9.20', 'friendlyName')
init('1.2.840.113549.1.9.21', 'localKeyId')
init('1.2.840.113549.1.9.22.1', 'x509Certificate')

// pkcs#12 safe bags
init('1.2.840.113549.1.12.10.1.1', 'keyBag')
init('1.2.840.113549.1.12.10.1.2', 'pkcs8ShroudedKeyBag')
init('1.2.840.113549.1.12.10.1.3', 'certBag')
init('1.2.840.113549.1.12.10.1.4', 'crlBag')
init('1.2.840.113549.1.12.10.1.5', 'secretBag')
init('1.2.840.113549.1.12.10.1.6', 'safeContentsBag')

// password-based-encryption for pkcs#12
init('1.2.840.113549.1.5.13', 'pkcs5PBES2')
init('1.2.840.113549.1.5.12', 'pkcs5PBKDF2')
init('1.2.840.113549.1.12.1.1', 'pbeWithSHAAnd128BitRC4')
init('1.2.840.113549.1.12.1.2', 'pbeWithSHAAnd40BitRC4')
init('1.2.840.113549.1.12.1.3', 'pbeWithSHAAnd3-KeyTripleDES-CBC')
init('1.2.840.113549.1.12.1.4', 'pbeWithSHAAnd2-KeyTripleDES-CBC')
init('1.2.840.113549.1.12.1.5', 'pbeWithSHAAnd128BitRC2-CBC')
init('1.2.840.113549.1.12.1.6', 'pbewithSHAAnd40BitRC2-CBC')

// hmac OIDs
init('1.2.840.113549.2.7', 'hmacWithSHA1')
init('1.2.840.113549.2.8', 'hmacWithSHA224')
init('1.2.840.113549.2.9', 'hmacWithSHA256')
init('1.2.840.113549.2.10', 'hmacWithSHA384')
init('1.2.840.113549.2.11', 'hmacWithSHA512')

// symmetric key algorithm oids
init('1.2.840.113549.3.7', 'des-EDE3-CBC')
init('2.16.840.1.101.3.4.1.2', 'aes128-CBC')
init('2.16.840.1.101.3.4.1.22', 'aes192-CBC')
init('2.16.840.1.101.3.4.1.42', 'aes256-CBC')

// certificate issuer/subject OIDs
init('2.5.4.3', 'commonName')
init('2.5.4.5', 'serialName')
init('2.5.4.6', 'countryName')
init('2.5.4.7', 'localityName')
init('2.5.4.8', 'stateOrProvinceName')
init('2.5.4.10', 'organizationName')
init('2.5.4.11', 'organizationalUnitName')

// X.509 extension OIDs
init('2.16.840.1.113730.1.1', 'nsCertType')
// init('2.5.29.1', 'authorityKeyIdentifier', true) deprecated, use .35
init('2.5.29.2', 'keyAttributes', true) // obsolete, use .37 or .15
// init('2.5.29.3', 'certificatePolicies', true) deprecated, use .32
init('2.5.29.4', 'keyUsageRestriction', true) // obsolete, use .37 or .15
// init('2.5.29.5', 'policyMapping', true) deprecated, use .33
init('2.5.29.6', 'subtreesConstraint', true) // obsolete, use .30
// init('2.5.29.7', 'subjectAltName', true) deprecated, use .17
// init('2.5.29.8', 'issuerAltName', true) deprecated, use .18
init('2.5.29.9', 'subjectDirectoryAttributes', true)
// init('2.5.29.10', 'basicConstraints', true) deprecated, use .19
// init('2.5.29.11', 'nameConstraints', true) deprecated, use .30
// init('2.5.29.12', 'policyConstraints', true) deprecated, use .36
// init('2.5.29.13', 'basicConstraints', true) deprecated, use .19
init('2.5.29.14', 'subjectKeyIdentifier')
init('2.5.29.15', 'keyUsage')
init('2.5.29.16', 'privateKeyUsagePeriod', true)
init('2.5.29.17', 'subjectAltName')
init('2.5.29.18', 'issuerAltName')
init('2.5.29.19', 'basicConstraints')
init('2.5.29.20', 'cRLNumber', true)
init('2.5.29.21', 'cRLReason', true)
init('2.5.29.22', 'expirationDate', true)
init('2.5.29.23', 'instructionCode', true)
init('2.5.29.24', 'invalidityDate', true)
// init('2.5.29.25', 'cRLDistributionPoints', true) deprecated, use .31
// init('2.5.29.26', 'issuingDistributionPoint', true) deprecated, use .28
init('2.5.29.27', 'deltaCRLIndicator', true)
init('2.5.29.28', 'issuingDistributionPoint', true)
init('2.5.29.29', 'certificateIssuer', true)
init('2.5.29.30', 'nameConstraints', true)
init('2.5.29.31', 'cRLDistributionPoints')
init('2.5.29.32', 'certificatePolicies')
init('2.5.29.33', 'policyMappings', true)
// init('2.5.29.34', 'policyConstraints', true) deprecated, use .36
init('2.5.29.35', 'authorityKeyIdentifier')
init('2.5.29.36', 'policyConstraints', true)
init('2.5.29.37', 'extKeyUsage')
init('2.5.29.46', 'freshestCRL', true)
init('2.5.29.54', 'inhibitAnyPolicy', true)

// extKeyUsage purposes
init('1.3.6.1.4.1.11129.2.4.2', 'timestampList')
init('1.3.6.1.5.5.7.1.1', 'authorityInfoAccess')
init('1.3.6.1.5.5.7.3.1', 'serverAuth')
init('1.3.6.1.5.5.7.3.2', 'clientAuth')
init('1.3.6.1.5.5.7.3.3', 'codeSigning')
init('1.3.6.1.5.5.7.3.4', 'emailProtection')
init('1.3.6.1.5.5.7.3.8', 'timeStamping')
