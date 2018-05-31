'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { inspect } from 'util'
import { createVerify, createSign, createHash } from 'crypto'
import { sign as ed25519 } from 'tweetnacl'
import { PEM, ASN1, Class, Tag, Template, Captures } from '@fidm/asn1'
import { getOID, getOIDName } from './common'

/**
 * ASN.1 Template for PKCS#8 Public Key.
 */
export const publicKeyValidator: Template = {
  name: 'PublicKeyInfo',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  capture: 'publicKeyInfo',
  value: [{
    name: 'PublicKeyInfo.AlgorithmIdentifier',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    value: [{
      name: 'PublicKeyAlgorithmIdentifier.algorithm',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
      capture: 'publicKeyOID',
    }],
  }, {
    name: 'PublicKeyInfo.PublicKey',
    class: Class.UNIVERSAL,
    tag: Tag.BITSTRING,
    capture: 'publicKey',
  }],
}

/**
 * ASN.1 Template for PKCS#8 Private Key. https://tools.ietf.org/html/rfc5208
 */
export const privateKeyValidator: Template = {
  name: 'PrivateKeyInfo',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  capture: 'privateKeyInfo',
  value: [{
    name: 'PrivateKeyInfo.Version',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyVersion',
  }, {
    name: 'PrivateKeyInfo.AlgorithmIdentifier',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    value: [{
      name: 'PrivateKeyAlgorithmIdentifier.algorithm',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
      capture: 'privateKeyOID',
    }],
  }, {
    name: 'PrivateKeyInfo.PrivateKey',
    class: Class.UNIVERSAL,
    tag: Tag.OCTETSTRING,
    capture: 'privateKey',
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

const rsaPrivateKeyValidator: Template = {
  // RSAPrivateKey
  name: 'RSAPrivateKey',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    // Version (INTEGER)
    name: 'RSAPrivateKey.version',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyVersion',
  }, {
    // modulus (n)
    name: 'RSAPrivateKey.modulus',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyModulus',
  }, {
    // publicExponent (e)
    name: 'RSAPrivateKey.publicExponent',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyPublicExponent',
  }, {
    // privateExponent (d)
    name: 'RSAPrivateKey.privateExponent',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyPrivateExponent',
  }, {
    // prime1 (p)
    name: 'RSAPrivateKey.prime1',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyPrime1',
  }, {
    // prime2 (q)
    name: 'RSAPrivateKey.prime2',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyPrime2',
  }, {
    // exponent1 (d mod (p-1))
    name: 'RSAPrivateKey.exponent1',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyExponent1',
  }, {
    // exponent2 (d mod (q-1))
    name: 'RSAPrivateKey.exponent2',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyExponent2',
  }, {
    // coefficient ((inverse of q) mod p)
    name: 'RSAPrivateKey.coefficient',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyCoefficient',
  }],
}

const EdDSAPrivateKeyOIDs = [
  // https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
  getOID('X25519'),
  getOID('X448'),
  getOID('Ed25519'),
  getOID('Ed448'),
]

export type Verifier = (this: PublicKey, data: Buffer, signature: Buffer) => boolean

/**
 * PKCS#8 Public Key
 */
export class PublicKey {
  /**
   * Parse an PublicKey for X.509 certificate from PKCS#8 PEM formatted buffer or PKCS#1 RSA PEM formatted buffer.
   * @param pem PEM formatted buffer
   */
  static fromPEM (pem: Buffer): PublicKey {
    const msg = PEM.parse(pem)[0]
    if (msg.procType.includes('ENCRYPTED')) {
      throw new Error('Could not convert public key from PEM, PEM is encrypted.');
    }

    const obj = ASN1.fromDER(msg.body, true)
    switch (msg.type) {
    case 'PUBLIC KEY': // PKCS#8
      return new PublicKey(obj)
    case 'RSA PUBLIC KEY': // PKCS#1
      const _pkcs8 = ASN1.Seq([
        // AlgorithmIdentifier
        ASN1.Seq([
          // algorithm
          ASN1.OID(getOID('rsaEncryption')),
          // optional parameters
          ASN1.Null(),
        ]),
        // PublicKey
        ASN1.BitString(obj.DER),
      ])
      return new PublicKey(_pkcs8)
    default:
      throw new Error('Could not convert public key from PEM, recommend PKCS#8 PEM')
    }
  }

  /**
   * Registers an external Verifier with object identifier.
   * Built-in verifiers: Ed25519, RSA, others see https://nodejs.org/api/crypto.html#crypto_class_verify
   * ```js
   * PublicKey.addVerifier(getOID('Ed25519'), function (this: PublicKey, data: Buffer, signature: Buffer): boolean {
   *   return ed25519.detached.verify(data, signature, this.keyRaw)
   * })
   * ```
   * @param oid algorithm object identifier
   * @param fn Verifier function
   */
  static addVerifier (oid: string, fn: Verifier) {
    oid = getOID(oid)
    if (oid === '') {
      throw new Error(`Invalid object identifier: ${oid}`)
    }
    if (PublicKey._verifiers[oid] != null) {
      throw new Error(`Verifier ${oid} exists`)
    }
    PublicKey._verifiers[oid] = fn
  }
  private static _verifiers: { [index: string]: Verifier } = Object.create(null)

  readonly oid: string
  readonly algo: string
  protected _pkcs8: ASN1
  protected _keyRaw: Buffer
  protected _finalKey: Buffer
  protected _finalPEM: string
  constructor (obj: ASN1) {
    const captures: Captures = {}
    const err = obj.validate(publicKeyValidator, captures)
    if (err != null) {
      throw new Error('Cannot read X.509 public key: ' + err.message)
    }

    this.oid = ASN1.parseOID(captures.publicKeyOID.bytes)
    this.algo = getOIDName(this.oid)
    this._pkcs8 = obj
    this._keyRaw = ASN1.parseBitString(captures.publicKey.bytes).buf
    this._finalKey = this._keyRaw
    this._finalPEM = ''
  }

  /**
   * underlying key buffer
   */
  get keyRaw (): Buffer {
    return this._finalKey
  }

  /**
   * Returns true if the provided data and the given signature matched.
   * ```js
   * certificate.publicKey.verify(data, signature, 'sha256') // => true or false
   * ```
   * @param data data to verify
   * @param signature signature that signed by private key
   * @param hashAlgorithm hash algorithm, such as 'sha256', 'sha1'
   */
  verify (data: Buffer, signature: Buffer, hashAlgorithm: string): boolean {
    const verifier = PublicKey._verifiers[this.oid]
    if (verifier != null) {
      const sum = createHash(hashAlgorithm).update(data).digest()
      return verifier.call(this, sum, signature)
    }

    const verify = createVerify(hashAlgorithm)
    verify.update(data)
    return verify.verify(this.toPEM(), signature)
  }

  /**
   * Returns the digest of the PublicKey with given hash algorithm.
   * ```js
   * certificate.publicKey.getFingerprint('sha1', 'PublicKey') // => Buffer
   * ```
   * @param hashAlgorithm hash algorithm, such as 'sha256', 'sha1'
   * @param type 'PublicKey' or 'PublicKeyInfo'
   */
  getFingerprint (hashAlgorithm: string, type: string = 'PublicKey'): Buffer {
    let bytes
    switch (type) {
    case 'PublicKeyInfo':
      bytes = this._pkcs8.DER
      break;
    case 'PublicKey':
      bytes = this._keyRaw
      break;
    default:
      throw new Error(`Unknown fingerprint type "${type}".`)
    }

    const hasher = createHash(hashAlgorithm)
    hasher.update(bytes)
    return hasher.digest()
  }

  /**
   * Returns an ASN.1 object of this PublicKey
   */
  toASN1 (): ASN1 {
    return this._pkcs8
  }

  /**
   * Returns an DER formatted buffer of this PublicKey
   */
  toDER (): Buffer {
    return this._pkcs8.DER
  }

  /**
   * Returns an PEM formatted string of this PublicKey
   */
  toPEM (): string {
    if (this._finalPEM === '') {
      this._finalPEM = new PEM('PUBLIC KEY', this._pkcs8.DER).toString()
    }
    return this._finalPEM
  }

  /**
   * Return a friendly JSON object for debuging.
   */
  toJSON (): any {
    return {
      oid: this.oid,
      algo: this.algo,
      publicKey: this._keyRaw,
    }
  }

  protected [inspect.custom] (_depth: any, options: any): string {
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

export type Signer = (this: PrivateKey, data: Buffer) => Buffer
/**
 * PKCS#8 Private Key
 */
export class PrivateKey {
  /**
   * Parse an PrivateKey for X.509 certificate from PKCS#8 PEM formatted buffer or PKCS#1 RSA PEM formatted buffer.
   * @param pem PEM formatted buffer
   */
  static fromPEM (pem: Buffer): PrivateKey {
    const msg = PEM.parse(pem)[0]

    if (msg.procType.includes('ENCRYPTED')) {
      throw new Error('Could not convert private key from PEM, PEM is encrypted.');
    }

    let obj = ASN1.fromDER(msg.body, true)
    switch (msg.type) {
    case 'PRIVATE KEY': // PKCS#8
      return new PrivateKey(obj)
    case 'RSA PRIVATE KEY': // PKCS#1
      obj = ASN1.Seq([
        // Version (INTEGER)
        obj.value[0],
        // AlgorithmIdentifier
        ASN1.Seq([
          // algorithm
          ASN1.OID(getOID('rsaEncryption')),
          // optional parameters
          ASN1.Null(),
        ]),
        // PrivateKey
        new ASN1(Class.UNIVERSAL, Tag.OCTETSTRING, obj.DER),
      ])
      return new PrivateKey(obj)
    default:
      throw new Error('Could not convert private key from PEM, recommend PKCS#8 PEM')
    }
  }

  /**
   * Registers an external Signer with object identifier.
   * Built-in verifiers: Ed25519, RSA, others see https://nodejs.org/api/crypto.html#crypto_class_sign
   * ```js
   * PrivateKey.addSigner(getOID('Ed25519'), function (this: PrivateKey, data: Buffer): Buffer {
   *   const key = this.keyRaw
   *   if (key.length !== 64) {
   *     throw new Error('Invalid signing key.')
   *   }
   *   return Buffer.from(ed25519.detached(data, key))
   * })
   * ```
   * @param oid algorithm object identifier
   * @param fn Verifier function
   */
  static addSigner (oid: string, fn: Signer) {
    oid = getOID(oid)
    if (oid === '') {
      throw new Error(`Invalid object identifier: ${oid}`)
    }
    if (PrivateKey._signers[oid] != null) {
      throw new Error(`Signer ${oid} exists`)
    }
    PrivateKey._signers[oid] = fn
  }
  private static _signers: { [index: string]: Signer } = Object.create(null)

  readonly version: number
  readonly oid: string
  readonly algo: string
  protected _pkcs8: ASN1
  protected _keyRaw: Buffer
  protected _publicKeyRaw: Buffer | null
  protected _finalKey: Buffer
  protected _finalPEM: string
  constructor (obj: ASN1) {
    // get RSA params
    const captures: Captures = Object.create(null)
    const err = obj.validate(privateKeyValidator, captures)
    if (err != null) {
      throw new Error('Cannot read X.509 private key: ' + err.message)
    }

    this.version = ASN1.parseIntegerNum(captures.privateKeyVersion.bytes) + 1
    this.oid = ASN1.parseOID(captures.privateKeyOID.bytes)
    this.algo = getOIDName(this.oid)
    this._pkcs8 = obj
    this._keyRaw = captures.privateKey.bytes
    this._publicKeyRaw = null
    this._finalKey = this._keyRaw
    this._finalPEM = ''

    if (EdDSAPrivateKeyOIDs.includes(this.oid)) {
      this._finalKey = this._keyRaw = ASN1.parseDER(this._keyRaw, Class.UNIVERSAL, Tag.OCTETSTRING).bytes
      if (this.oid === '1.3.101.112') {
        const keypair = ed25519.keyPair.fromSeed(this._keyRaw)
        this._publicKeyRaw = Buffer.from(keypair.publicKey)
        this._finalKey = Buffer.from(keypair.secretKey)
      } else if (this.version === 2) {
        for (const val of obj.mustCompound()) {
          if (val.class === Class.CONTEXT_SPECIFIC && val.tag === 1) {
            this._publicKeyRaw = ASN1.parseBitString(val.bytes).buf
            this._finalKey = Buffer.concat([this._keyRaw, this._publicKeyRaw as Buffer])
          }
        }
      }
    }
  }

  /**
   * underlying key buffer
   */
  get keyRaw (): Buffer {
    return this._finalKey
  }

  /**
   * Returns publicKey buffer, it is used for Ed25519/Ed448.
   */
  get publicKeyRaw (): Buffer | null {
    return this._publicKeyRaw
  }

  /**
   * Returns signature for the given data and hash algorithm.
   * @param data
   * @param hashAlgorithm
   */
  sign (data: Buffer, hashAlgorithm: string): Buffer {
    const signer = PrivateKey._signers[this.oid]
    if (signer != null) {
      const sum = createHash(hashAlgorithm).update(data).digest()
      return signer.call(this, sum)
    }

    const sign = createSign(hashAlgorithm)
    sign.update(data)
    return sign.sign(this.toPEM())
  }

  /**
   * Returns an ASN.1 object of this PrivateKey
   */
  toASN1 (): ASN1 {
    return this._pkcs8
  }

  /**
   * Returns an DER formatted buffer of this PrivateKey
   */
  toDER (): Buffer {
    return this._pkcs8.DER
  }

  /**
   * Returns an PEM formatted string of this PrivateKey
   */
  toPEM (): string {
    if (this._finalPEM === '') {
      this._finalPEM = new PEM('PRIVATE KEY', this._pkcs8.DER).toString()
    }
    return this._finalPEM
  }

  /**
   * Return a friendly JSON object for debuging.
   */
  toJSON (): any {
    return {
      version: this.version,
      oid: this.oid,
      algo: this.algo,
      privateKey: this._keyRaw,
      publicKey: this._publicKeyRaw,
    }
  }

  protected [inspect.custom] (_depth: any, options: any): string {
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

/**
 * PKCS#1 RSA Public Key
 */
export class RSAPublicKey extends PublicKey {
  static fromPublicKey (publicKey: PublicKey): RSAPublicKey {
    return new RSAPublicKey(publicKey.toASN1())
  }

  readonly modulus: string // modulus, hex string
  readonly exponent: number // public exponent
  protected _pkcs1: ASN1
  constructor (obj: ASN1) {
    super(obj)
    if (getOID(this.oid) !== getOID('rsaEncryption')) {
      throw new Error(`Invalid RSA public key, unknown OID: ${this.oid}`)
    }
    // get RSA params
    const captures: Captures = Object.create(null)
    this._pkcs1 = ASN1.fromDER(this._keyRaw, true)
    const err = this._pkcs1.validate(rsaPublicKeyValidator, captures)
    if (err != null) {
      throw new Error('Cannot read RSA public key: ' + err.message)
    }

    this.modulus = ASN1.parseIntegerStr(captures.publicKeyModulus.bytes)
    this.exponent = ASN1.parseIntegerNum(captures.publicKeyExponent.bytes)
  }

  /**
   * Returns an PKCS#1 ASN.1 object of this RSAPublicKey
   */
  toASN1 (): ASN1 {
    return this._pkcs1
  }

  /**
   * Returns an PKCS#1 DER formatted buffer of this RSAPublicKey
   */
  toDER (): Buffer {
    return this._keyRaw
  }

  /**
   * Returns an PKCS#1 PEM formatted string of this RSAPublicKey
   */
  toPEM (): string {
    if (this._finalPEM === '') {
      this._finalPEM = new PEM('RSA PUBLIC KEY', this._keyRaw).toString()
    }
    return this._finalPEM
  }

  /**
   * Returns an PKCS#8 PEM formatted string of this RSAPublicKey
   */
  toPublicKeyPEM (): string {
    return new PEM('PUBLIC KEY', this._pkcs8.DER).toString()
  }

  /**
   * Return a friendly JSON object for debuging.
   */
  toJSON (): any {
    return {
      oid: this.oid,
      algo: this.algo,
      modulus: trimLeadingZeroByte(this.modulus),
      exponent: this.exponent,
    }
  }

  protected [inspect.custom] (_depth: any, options: any): string {
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

/**
 * PKCS#1 RSA Private Key
 */
export class RSAPrivateKey extends PrivateKey {
  static fromPrivateKey (privateKey: PrivateKey): RSAPrivateKey {
    return new RSAPrivateKey(privateKey.toASN1())
  }

  readonly publicExponent: number
  readonly privateExponent: string
  readonly modulus: string
  readonly prime1: string
  readonly prime2: string
  readonly exponent1: string
  readonly exponent2: string
  readonly coefficient: string
  protected _pkcs1: ASN1
  constructor (obj: ASN1) {
    super(obj)
    if (getOID(this.oid) !== getOID('rsaEncryption')) {
      throw new Error(`Invalid RSA private key, unknown OID: ${this.oid}`)
    }
    // get RSA params
    const captures: Captures = Object.create(null)
    this._pkcs1 = ASN1.fromDER(this._keyRaw, true)
    const err = this._pkcs1.validate(rsaPrivateKeyValidator, captures)
    if (err != null) {
      throw new Error('Cannot read RSA private key: ' + err.message)
    }

    this.publicExponent = ASN1.parseIntegerNum(captures.privateKeyPublicExponent.bytes)
    this.privateExponent = ASN1.parseIntegerStr(captures.privateKeyPrivateExponent.bytes)
    this.modulus = ASN1.parseIntegerStr(captures.privateKeyModulus.bytes)
    this.prime1 = ASN1.parseIntegerStr(captures.privateKeyPrime1.bytes)
    this.prime2 = ASN1.parseIntegerStr(captures.privateKeyPrime2.bytes)
    this.exponent1 = ASN1.parseIntegerStr(captures.privateKeyExponent1.bytes)
    this.exponent2 = ASN1.parseIntegerStr(captures.privateKeyExponent2.bytes)
    this.coefficient = ASN1.parseIntegerStr(captures.privateKeyCoefficient.bytes)
  }

  /**
   * Returns an PKCS#1 ASN.1 object of this RSAPrivateKey
   */
  toASN1 (): ASN1 {
    return this._pkcs1
  }

  /**
   * Returns an PKCS#1 DER formatted buffer of this RSAPrivateKey
   */
  toDER (): Buffer {
    return this._keyRaw
  }

  /**
   * Returns an PKCS#1 PEM formatted string of this RSAPrivateKey
   */
  toPEM (): string {
    if (this._finalPEM === '') {
      this._finalPEM = new PEM('RSA PRIVATE KEY', this._keyRaw).toString()
    }
    return this._finalPEM
  }

  /**
   * Returns an PKCS#8 PEM formatted string of this RSAPrivateKey
   */
  toPrivateKeyPEM (): string {
    return new PEM('PRIVATE KEY', this._pkcs8.DER).toString()
  }

  /**
   * Return a friendly JSON object for debuging.
   */
  toJSON (): any {
    return {
      version: this.version,
      oid: this.oid,
      algo: this.algo,
      publicExponent: this.publicExponent,
      privateExponent: trimLeadingZeroByte(this.privateExponent),
      modulus: trimLeadingZeroByte(this.modulus),
      prime1: trimLeadingZeroByte(this.prime1),
      prime2: trimLeadingZeroByte(this.prime2),
      exponent1: trimLeadingZeroByte(this.exponent1),
      exponent2: trimLeadingZeroByte(this.exponent2),
      coefficient: trimLeadingZeroByte(this.coefficient),
    }
  }

  protected [inspect.custom] (_depth: any, options: any): string {
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

// leading 00 byte is signed representation for BigInteger
// https://stackoverflow.com/questions/8515691/getting-1-byte-extra-in-the-modulus-rsa-key-and-sometimes-for-exponents-also
function trimLeadingZeroByte (hex: string): string {
  return (hex.length % 8 !== 0) && hex.startsWith('00') ? hex.slice(2) : hex
}

PublicKey.addVerifier(getOID('Ed25519'), function (this: PublicKey, data: Buffer, signature: Buffer): boolean {
  return ed25519.detached.verify(data, signature, this.keyRaw)
})

PrivateKey.addSigner(getOID('Ed25519'), function (this: PrivateKey, data: Buffer): Buffer {
  const key = this.keyRaw
  if (key.length !== 64) {
    throw new Error('Invalid signing key.')
  }
  return Buffer.from(ed25519.detached(data, key))
})
