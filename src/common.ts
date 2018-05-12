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

  mustHas (steps: number, message: string = 'Too few bytes to parse.') {
    const requested = this.end + steps
    if (requested > this.buf.length) {
      const error = new Error(message) as any
      error.available = this.buf.length
      error.requested = requested
      throw error
    }
    this.walk(0)
  }

  mustWalk (steps: number, message?: string) {
    this.mustHas(steps, message)
    this.walk(steps)
  }
}

const oids: { [index: string]: string } = Object.create(null)
const oidReg = /^[0-9.]+$/

// getOID returns oid or ''
export function getOID (nameOrId: string): string {
  if (oidReg.test(nameOrId) && oids[nameOrId] !== '') {
    return nameOrId
  }
  return oids[nameOrId] == null ? '' : oids[nameOrId]
}

// getOIDName return name or oid
export function getOIDName (nameOrId: string): string {
  if (!oidReg.test(nameOrId) && oids[nameOrId] !== '') {
    return nameOrId
  }
  return oids[nameOrId] == null ? '' : oids[nameOrId]
}

// set id to name mapping and name to id mapping
function initOID (id: string, name: string, unidirection: boolean = false) {
  oids[id] = name

  if (!unidirection) {
    oids[name] = id
  }
}

// algorithm OIDs
initOID('1.2.840.113549.1.1.1', 'rsaEncryption')
// initOID('1.2.840.113549.1.1.2', 'md2WithRSAEncryption') not implemented
// initOID('1.2.840.113549.1.1.3', 'md4WithRSAEncryption') not implemented
initOID('1.2.840.113549.1.1.4', 'md5WithRSAEncryption')
initOID('1.2.840.113549.1.1.5', 'sha1WithRSAEncryption')
initOID('1.2.840.113549.1.1.7', 'RSAES-OAEP')
initOID('1.2.840.113549.1.1.8', 'mgf1')
initOID('1.2.840.113549.1.1.9', 'pSpecified')
initOID('1.2.840.113549.1.1.10', 'RSASSA-PSS')
initOID('1.2.840.113549.1.1.11', 'sha256WithRSAEncryption')
initOID('1.2.840.113549.1.1.12', 'sha384WithRSAEncryption')
initOID('1.2.840.113549.1.1.13', 'sha512WithRSAEncryption')
initOID('1.2.840.10040.4.3', 'dsa-with-sha1')
initOID('1.3.14.3.2.7', 'desCBC')
initOID('1.3.14.3.2.26', 'sha1')
initOID('2.16.840.1.101.3.4.2.1', 'sha256')
initOID('2.16.840.1.101.3.4.2.2', 'sha384')
initOID('2.16.840.1.101.3.4.2.3', 'sha512')
initOID('1.2.840.113549.2.5', 'md5')

// pkcs#7 content types
initOID('1.2.840.113549.1.7.1', 'data')
initOID('1.2.840.113549.1.7.2', 'signedData')
initOID('1.2.840.113549.1.7.3', 'envelopedData')
initOID('1.2.840.113549.1.7.4', 'signedAndEnvelopedData')
initOID('1.2.840.113549.1.7.5', 'digestedData')
initOID('1.2.840.113549.1.7.6', 'encryptedData')

// pkcs#9 oids
initOID('1.2.840.113549.1.9.1', 'emailAddress')
initOID('1.2.840.113549.1.9.2', 'unstructuredName')
initOID('1.2.840.113549.1.9.3', 'contentType')
initOID('1.2.840.113549.1.9.4', 'messageDigest')
initOID('1.2.840.113549.1.9.5', 'signingTime')
initOID('1.2.840.113549.1.9.6', 'counterSignature')
initOID('1.2.840.113549.1.9.7', 'challengePassword')
initOID('1.2.840.113549.1.9.8', 'unstructuredAddress')
initOID('1.2.840.113549.1.9.14', 'extensionRequest')
initOID('1.2.840.113549.1.9.20', 'friendlyName')
initOID('1.2.840.113549.1.9.21', 'localKeyId')
initOID('1.2.840.113549.1.9.22.1', 'x509Certificate')

// pkcs#12 safe bags
initOID('1.2.840.113549.1.12.10.1.1', 'keyBag')
initOID('1.2.840.113549.1.12.10.1.2', 'pkcs8ShroudedKeyBag')
initOID('1.2.840.113549.1.12.10.1.3', 'certBag')
initOID('1.2.840.113549.1.12.10.1.4', 'crlBag')
initOID('1.2.840.113549.1.12.10.1.5', 'secretBag')
initOID('1.2.840.113549.1.12.10.1.6', 'safeContentsBag')

// password-based-encryption for pkcs#12
initOID('1.2.840.113549.1.5.13', 'pkcs5PBES2')
initOID('1.2.840.113549.1.5.12', 'pkcs5PBKDF2')
initOID('1.2.840.113549.1.12.1.1', 'pbeWithSHAAnd128BitRC4')
initOID('1.2.840.113549.1.12.1.2', 'pbeWithSHAAnd40BitRC4')
initOID('1.2.840.113549.1.12.1.3', 'pbeWithSHAAnd3-KeyTripleDES-CBC')
initOID('1.2.840.113549.1.12.1.4', 'pbeWithSHAAnd2-KeyTripleDES-CBC')
initOID('1.2.840.113549.1.12.1.5', 'pbeWithSHAAnd128BitRC2-CBC')
initOID('1.2.840.113549.1.12.1.6', 'pbewithSHAAnd40BitRC2-CBC')

// hmac OIDs
initOID('1.2.840.113549.2.7', 'hmacWithSHA1')
initOID('1.2.840.113549.2.8', 'hmacWithSHA224')
initOID('1.2.840.113549.2.9', 'hmacWithSHA256')
initOID('1.2.840.113549.2.10', 'hmacWithSHA384')
initOID('1.2.840.113549.2.11', 'hmacWithSHA512')

// symmetric key algorithm oids
initOID('1.2.840.113549.3.7', 'des-EDE3-CBC')
initOID('2.16.840.1.101.3.4.1.2', 'aes128-CBC')
initOID('2.16.840.1.101.3.4.1.22', 'aes192-CBC')
initOID('2.16.840.1.101.3.4.1.42', 'aes256-CBC')

// certificate issuer/subject OIDs
initOID('2.5.4.3', 'commonName')
initOID('2.5.4.5', 'serialName')
initOID('2.5.4.6', 'countryName')
initOID('2.5.4.7', 'localityName')
initOID('2.5.4.8', 'stateOrProvinceName')
initOID('2.5.4.10', 'organizationName')
initOID('2.5.4.11', 'organizationalUnitName')

// X.509 extension OIDs
initOID('2.16.840.1.113730.1.1', 'nsCertType')
// initOID('2.5.29.1', 'authorityKeyIdentifier', true) deprecated, use .35
initOID('2.5.29.2', 'keyAttributes', true) // obsolete, use .37 or .15
// initOID('2.5.29.3', 'certificatePolicies', true) deprecated, use .32
initOID('2.5.29.4', 'keyUsageRestriction', true) // obsolete, use .37 or .15
// initOID('2.5.29.5', 'policyMapping', true) deprecated, use .33
initOID('2.5.29.6', 'subtreesConstraint', true) // obsolete, use .30
// initOID('2.5.29.7', 'subjectAltName', true) deprecated, use .17
// initOID('2.5.29.8', 'issuerAltName', true) deprecated, use .18
initOID('2.5.29.9', 'subjectDirectoryAttributes', true)
// initOID('2.5.29.10', 'basicConstraints', true) deprecated, use .19
// initOID('2.5.29.11', 'nameConstraints', true) deprecated, use .30
// initOID('2.5.29.12', 'policyConstraints', true) deprecated, use .36
// initOID('2.5.29.13', 'basicConstraints', true) deprecated, use .19
initOID('2.5.29.14', 'subjectKeyIdentifier')
initOID('2.5.29.15', 'keyUsage')
initOID('2.5.29.16', 'privateKeyUsagePeriod', true)
initOID('2.5.29.17', 'subjectAltName')
initOID('2.5.29.18', 'issuerAltName')
initOID('2.5.29.19', 'basicConstraints')
initOID('2.5.29.20', 'cRLNumber', true)
initOID('2.5.29.21', 'cRLReason', true)
initOID('2.5.29.22', 'expirationDate', true)
initOID('2.5.29.23', 'instructionCode', true)
initOID('2.5.29.24', 'invalidityDate', true)
// initOID('2.5.29.25', 'cRLDistributionPoints', true) deprecated, use .31
// initOID('2.5.29.26', 'issuingDistributionPoint', true) deprecated, use .28
initOID('2.5.29.27', 'deltaCRLIndicator', true)
initOID('2.5.29.28', 'issuingDistributionPoint', true)
initOID('2.5.29.29', 'certificateIssuer', true)
initOID('2.5.29.30', 'nameConstraints', true)
initOID('2.5.29.31', 'cRLDistributionPoints')
initOID('2.5.29.32', 'certificatePolicies')
initOID('2.5.29.33', 'policyMappings', true)
// initOID('2.5.29.34', 'policyConstraints', true) deprecated, use .36
initOID('2.5.29.35', 'authorityKeyIdentifier')
initOID('2.5.29.36', 'policyConstraints', true)
initOID('2.5.29.37', 'extKeyUsage')
initOID('2.5.29.46', 'freshestCRL', true)
initOID('2.5.29.54', 'inhibitAnyPolicy', true)

// extKeyUsage purposes
initOID('1.3.6.1.4.1.11129.2.4.2', 'timestampList')
initOID('1.3.6.1.5.5.7.1.1', 'authorityInfoAccess')
initOID('1.3.6.1.5.5.7.3.1', 'serverAuth')
initOID('1.3.6.1.5.5.7.3.2', 'clientAuth')
initOID('1.3.6.1.5.5.7.3.3', 'codeSigning')
initOID('1.3.6.1.5.5.7.3.4', 'emailProtection')
initOID('1.3.6.1.5.5.7.3.8', 'timeStamping')
