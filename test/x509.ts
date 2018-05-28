'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, deepEqual, ok } from 'assert'
import { suite, it } from 'tman'
import { Certificate, RSAPublicKey, PrivateKey } from '../src/index'

suite('X509', function () {
  it('should work for github certificate', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/github.crt'))
    strictEqual(cert.version, 3)
    strictEqual(cert.serialNumber, '0a0630427f5bbced6957396593b6451f')
    strictEqual(cert.signatureAlgorithm, 'sha256WithRsaEncryption')
    strictEqual(cert.subjectKeyIdentifier, 'c9c25361669d5fab25f426cd0f389aa849ea48a9')
    strictEqual(cert.authorityKeyIdentifier, '3dd350a5d6a0adeef34a600a65d321d4f8f8d60f')
    strictEqual(cert.keyUsage, 5)
    strictEqual(cert.ocspServer, 'http://ocsp.digicert.com')
    strictEqual(cert.issuingCertificateURL,
      'http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt')
    deepEqual(cert.dnsNames, [ 'github.com', 'www.github.com' ])
    strictEqual(cert.subject.commonName, 'github.com')
    strictEqual(cert.subject.organizationName, 'GitHub, Inc.')
    strictEqual(cert.subject.organizationalUnitName, '')
    strictEqual(cert.subject.countryName, 'US')
    strictEqual(cert.subject.localityName, 'San Francisco')
    strictEqual(cert.subject.serialName, '5157550')
    strictEqual(cert.issuer.commonName, 'DigiCert SHA2 Extended Validation Server CA')
    strictEqual(cert.issuer.organizationName, 'DigiCert Inc')
    strictEqual(cert.issuer.organizationalUnitName, 'www.digicert.com')
    strictEqual(cert.issuer.countryName, 'US')
    strictEqual(cert.issuer.localityName, '')
    strictEqual(cert.issuer.serialName, '')

    ok(cert.validFrom.valueOf() < Date.now())
    ok(cert.validTo.valueOf() > Date.now())
    ok(cert.publicKeyRaw.toString('hex')
      .startsWith('30820122300d06092a864886f70d01010105000382010f003082010a02820101'))
    ok(RSAPublicKey.fromPublicKey(cert.publicKey).modulus
      .startsWith('00c63caaf23c970c3ac14f28ad72707dd3ceb9b56073a4749b8a7746fd7a98424cc5301957'))

    const certL0 = Certificate.fromPEM(
      fs.readFileSync('./test/cert/github-root.crt'))
    const certL1 = Certificate.fromPEM(
      fs.readFileSync('./test/cert/github-issuer.crt'))
    ok(certL0.verifySubjectKeyIdentifier())
    ok(certL1.verifySubjectKeyIdentifier())
    ok(cert.verifySubjectKeyIdentifier())
    ok(cert.isIssuer(certL1))
    ok(certL1.isIssuer(certL0))
    strictEqual(certL0.checkSignature(certL1), null)
    strictEqual(certL1.checkSignature(cert), null)
  })

  it('should work for self-signed certificate', function () {
    const root = Certificate.fromPEM(fs.readFileSync('./test/cert/test-root.crt'))
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/test.crt'))
    ok(cert.isIssuer(root))
    ok(root.verifySubjectKeyIdentifier())
    ok(cert.verifySubjectKeyIdentifier())
    strictEqual(root.checkSignature(cert), null)
  })

  it('should support ecdsa certificate', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/ecdsa-server-cert.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ecdsa-server-key.pem'))

    ok(cert.verifySubjectKeyIdentifier())
    strictEqual(cert.issuer.commonName, 'Root CA')
    strictEqual(cert.subject.commonName, 'Server ECDSA cert')

    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256')
    ok(cert.publicKey.verify(data, signature, 'sha256'))
  })

  it('should support ed25519 certificate', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/ed25519-server-cert.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/ed25519-server-key.pem'))

    ok(cert.verifySubjectKeyIdentifier())
    strictEqual(cert.issuer.commonName, 'Root CA')
    strictEqual(cert.subject.commonName, 'Ed25519')

    privateKey.setPublicKey(cert.publicKey)
    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256')
    ok(cert.publicKey.verify(data, signature, 'sha256'))

    const clicert = Certificate.fromPEM(fs.readFileSync('./test/cert/ed25519-client-cert.pem'))
    ok(clicert.verifySubjectKeyIdentifier())
    strictEqual(clicert.issuer.commonName, 'CA')
    strictEqual(clicert.subject.commonName, 'Client-Ed25519')
  })

  it('should support RSASSA-PSS certificate', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/pss-server-cert.pem'))
    // const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/pss-server-key.pem'))

    ok(cert.verifySubjectKeyIdentifier())
    strictEqual(cert.issuer.commonName, 'Root CA')
    strictEqual(cert.subject.commonName, 'RSASSA-PSS')

    // Node.js can't support RSASSA-PSS
    // const data = Buffer.allocUnsafe(100)
    // const signature = privateKey.sign(data, 'sha256')
    // ok(cert.publicKey.verify(data, signature, 'sha256'))
  })

  it('should support other certificate 1', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/rootCA.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/rootCA.key'))

    ok(cert.verifySubjectKeyIdentifier())
    strictEqual(cert.issuer.commonName, 'rootCA')
    strictEqual(cert.subject.commonName, 'rootCA')

    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256')
    ok(cert.publicKey.verify(data, signature, 'sha256'))
  })

  it('should support other certificate 2', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/rootcert.pem'))
    const privateKey = PrivateKey.fromPEM(fs.readFileSync('./test/cert/rootkey.pem'))

    ok(cert.verifySubjectKeyIdentifier())
    strictEqual(cert.issuer.commonName, 'Root CA')
    strictEqual(cert.subject.commonName, 'Root CA')

    const data = Buffer.allocUnsafe(100)
    const signature = privateKey.sign(data, 'sha256')
    ok(cert.publicKey.verify(data, signature, 'sha256'))
  })
})
