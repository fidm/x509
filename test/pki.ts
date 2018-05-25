'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, ok } from 'assert'
import { suite, it } from 'tman'
import { sign as ed25519 } from 'tweetnacl'
import { Certificate } from '../src/x509'
import { PublicKey, PrivateKey, RSAPrivateKey } from '../src/pki'

PublicKey.addVerifier('1.3.101.112', function (this: PublicKey, data: Buffer, signature: Buffer): boolean {
  return ed25519.detached.verify(data, signature, this.raw)
})

PrivateKey.addSigner('1.3.101.112', function (this: PrivateKey, data: Buffer): Buffer {
  return Buffer.from(ed25519.detached(data, this.raw))
})

suite('PKI', function () {
  it('should work', function () {
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/test-root.key'))
    const privateKeyP8 = PrivateKey.fromPEM(fs.readFileSync('./test/cert/test-root.p8.key'))
    const privateKeyRSA = RSAPrivateKey.fromPrivateKey(privateKey)

    strictEqual(privateKey.algo, 'rsaEncryption')
    strictEqual(privateKeyP8.algo, 'rsaEncryption')
    strictEqual(privateKeyRSA.algo, 'rsaEncryption')
    strictEqual(privateKeyRSA.version, 0)
    strictEqual(privateKeyRSA.publicExponent, 65537)

    // Node.js can't support RSASSA-PSS
    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256').toString('hex')
    strictEqual(privateKeyP8.sign(data, 'sha256').toString('hex'), signature)
    strictEqual(privateKeyRSA.sign(data, 'sha256').toString('hex'), signature)
    strictEqual(RSAPrivateKey.fromPrivateKey(privateKeyP8).sign(data, 'sha256').toString('hex'), signature)

    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/test-root.crt'))
    ok(cert.publicKey.verify(data, Buffer.from(signature, 'hex'), 'sha256'))
  })

  it.skip('should support ed25519', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/ed25519-server-cert.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-server-key.pem'))

    strictEqual(cert.publicKey.raw.length, 32)
    strictEqual(privateKey.raw.length, 64) // 34 bytes?
    strictEqual(privateKey.algo, 'EdDSA25519')

    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256')
    ok(cert.publicKey.verify(data, signature, 'sha256'))

    const clicert = Certificate.fromPEM(fs.readFileSync('./test/cert/ed25519-client-cert.pem'))
    const cliprivateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-client-key.pem'))

    strictEqual(clicert.publicKey.raw.length, 32)
    strictEqual(cliprivateKey.raw.length, 64)
    strictEqual(cliprivateKey.algo, 'EdDSA25519')

    const data2 = Buffer.allocUnsafe(99)
    const signature2 = cliprivateKey.sign(data2, 'sha512')
    ok(clicert.publicKey.verify(data2, signature2, 'sha512'))
  })
})
