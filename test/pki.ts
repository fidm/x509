'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, ok, throws } from 'assert'
import { suite, it } from 'tman'
import { Certificate, PublicKey, PrivateKey, RSAPrivateKey } from '../src/index'

suite('PKI', function () {
  it('should work', function () {
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/test-root.key'))
    const privateKeyP8 = PrivateKey.fromPEM(fs.readFileSync('./test/cert/test-root.p8.key'))
    const privateKeyRSA = RSAPrivateKey.fromPrivateKey(privateKey)

    strictEqual(privateKey.algo, 'rsaEncryption')
    strictEqual(privateKeyP8.algo, 'rsaEncryption')
    strictEqual(privateKeyRSA.algo, 'rsaEncryption')
    strictEqual(privateKeyRSA.version, 1)
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

  it('should support ed25519', function () {
    const publicKey = PublicKey.fromPEM(fs.readFileSync('./test/cert/ed25519-key-public.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-key-simple.pem'))
    const fullPrivateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-key-full.pem'))

    strictEqual(publicKey.algo, 'Ed25519')
    strictEqual(privateKey.algo, 'Ed25519')
    strictEqual(fullPrivateKey.algo, 'Ed25519')
    strictEqual(publicKey.keyRaw.length, 32)
    strictEqual(privateKey.keyRaw.length, 32)
    strictEqual(fullPrivateKey.keyRaw.length, 64)

    const data = Buffer.allocUnsafe(100)
    const signature = fullPrivateKey.sign(data, 'sha256')
    ok(publicKey.verify(data, signature, 'sha256'))

    throws(() => privateKey.sign(data, 'sha256'))
    privateKey.setPublicKey(publicKey)
    strictEqual(privateKey.keyRaw.length, 64)
    ok(publicKey.verify(data, privateKey.sign(data, 'sha512'), 'sha512'))
  })

  it('should support ed25519 certificate', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/ed25519-server-cert.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-server-key.pem'))

    privateKey.setPublicKey(cert.publicKey)
    strictEqual(cert.publicKey.keyRaw.length, 32)
    strictEqual(privateKey.keyRaw.length, 64)
    strictEqual(privateKey.algo, 'Ed25519')

    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256')
    ok(cert.publicKey.verify(data, signature, 'sha256'))

    const certcli = Certificate.fromPEM(fs.readFileSync('./test/cert/ed25519-client-cert.pem'))
    const privateKeycli = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-client-key.pem'))

    privateKeycli.setPublicKey(certcli.publicKey)
    privateKeycli.setPublicKey(certcli.publicKey)
    strictEqual(certcli.publicKey.keyRaw.length, 32)
    strictEqual(privateKeycli.keyRaw.length, 64)
    strictEqual(privateKeycli.algo, 'Ed25519')

    const signaturecli = privateKeycli.sign(data, 'sha512')
    ok(certcli.publicKey.verify(data, signaturecli, 'sha512'))
    ok(cert.publicKey.verify(data, signaturecli, 'sha512') === false)
  })
})
