'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { Hash, createVerify } from 'crypto'
import { PEM } from './pem'
import { getOID } from './common'
import { ASN1, Class, Tag, Template, Captures } from './asn1'

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
export const publicKeyValidator: Template = {
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

export class RSAPublicKey {
  // Converts an RSA public key from PEM format.
  static FromPublicKeyPem (pem: Buffer): RSAPublicKey {
    const msg = PEM.parse(pem)[0]

    if (msg.type !== 'PUBLIC KEY' && msg.type !== 'RSA PUBLIC KEY') {
      throw new Error('Could not convert public key from PEM')
    }
    if (msg.procType.includes('ENCRYPTED')) {
      throw new Error('Could not convert public key from PEM; PEM is encrypted.');
    }

    return RSAPublicKey.fromPublicKeyASN1(ASN1.fromDER(msg.body))
  }

  static fromPublicKeyASN1 (obj: ASN1): RSAPublicKey {
    // get SubjectPublicKeyInfo
    const captures: Captures = Object.create(null)
    const err = obj.validate(publicKeyValidator, captures)
    if (err != null) {
      throw new Error('Cannot read X.509 public key: ' + err.message)
    }

    const oid = ASN1.parseOID(captures.publicKeyOID.bytes)
    if (oid !== getOID('rsaEncryption')) {
      throw new Error('Cannot read RSA public key. Unknown OID.')
    }
    return new RSAPublicKey(captures.rsaPublicKey)
  }

  private n: string // modulus, hex string
  private e: number // public exponent, hex string
  constructor (rsaPublicKey: ASN1) {
    // get RSA params
    const captures: Captures = Object.create(null)
    const err = rsaPublicKey.validate(rsaPublicKeyValidator, captures)
    if (err != null) {
      throw new Error('Cannot read X.509 public key: ' + err.message)
    }

    // leading 00 byte is signed representation for BigInteger
    // https://stackoverflow.com/questions/8515691/getting-1-byte-extra-in-the-modulus-rsa-key-and-sometimes-for-exponents-also
    this.n = ASN1.parseIntegerStr(captures.publicKeyModulus.bytes)
    this.e = ASN1.parseIntegerNum(captures.publicKeyExponent.bytes)
  }

  verify (data: Buffer, signature: Buffer, hashAgl: string = 'sha1'): boolean {
    const verify = createVerify(hashAgl)
    verify.update(data)
    return verify.verify(this.toPEM(), signature)
  }

  getFingerprint (hasher: Hash, type: string = 'RSAPublicKey'): Buffer {
    let bytes
    switch (type) {
    case 'RSAPublicKey':
      bytes = this.toASN1().toDER()
      break;
    case 'SubjectPublicKeyInfo':
      bytes = this.toPublicKeyASN1().toDER()
      break;
    default:
      throw new Error(`Unknown fingerprint type "${type}".`)
    }

    // hash public key bytes
    hasher.update(bytes)
    return hasher.digest()
  }

  toJSON () {
    return {
      n: this.n.startsWith('00') ? this.n.slice(2) : this.n,
      e: this.e,
    }
  }

  toASN1 (): ASN1 {
    // RSAPublicKey
    return ASN1.Seq([
      // modulus (n)
      ASN1.Integer(Buffer.from(this.n, 'hex')),
      // publicExponent (e)
      ASN1.Integer(this.e),
    ])
  }

  toPublicKeyASN1 (): ASN1 {
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
      ASN1.BitString(this.toASN1().toDER()),
    ])
  }

  toPEM (): string {
    return new PEM('RSA PUBLIC KEY', this.toASN1().toDER()).toString()
  }

  // Converts an RSA public key to PEM format (using a SubjectPublicKeyInfo).
  toPublicKeyPEM (): string {
    return new PEM('PUBLIC KEY', this.toPublicKeyASN1().toDER()).toString()
  }
}
