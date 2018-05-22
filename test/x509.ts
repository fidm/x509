'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, deepEqual, ok } from 'assert'
import { suite, it } from 'tman'
import { Certificate } from '../src/x509'

suite('X509', function () {
  it('should work for github certificate', function () {
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/github.crt'))
    strictEqual(cert.version, 2)
    strictEqual(cert.serialNumber, '0a0630427f5bbced6957396593b6451f')
    strictEqual(cert.signatureAlgorithm, 'sha256WithRSAEncryption')
    strictEqual(cert.subjectKeyIdentifier, 'c9c25361669d5fab25f426cd0f389aa849ea48a9')
    strictEqual(cert.authorityKeyIdentifier, '3dd350a5d6a0adeef34a600a65d321d4f8f8d60f')
    strictEqual(cert.ocspServer, 'http://ocsp.digicert.com')
    strictEqual(cert.issuingCertificateURL, 'http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt')
    deepEqual(cert.dnsNames, [ 'github.com', 'www.github.com' ])
    ok(cert.verifySubjectKeyIdentifier())
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
    ok(cert.publicKeyRaw.toString('hex').startsWith('30820122300d06092a864886f70d01010105000382010f003082010a02820101'))
    ok(cert.publicKey.toJSON().n.startsWith('c63caaf23c970c3ac14f28ad72707dd3ceb9b56073a4749b8a7746fd7a98424cc5301957'))
  })

  it('should work for self-signed certificate', function () {
    const rootcert = Certificate.fromPEM(fs.readFileSync('./test/cert/root.crt'))
    const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/test.crt'))
    ok(cert.isIssuer(rootcert))
    ok(rootcert.verify(cert))
    ok(rootcert.verifySubjectKeyIdentifier())
    ok(cert.verifySubjectKeyIdentifier())
  })
})
