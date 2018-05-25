'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

require('ts-node/register')
const fs = require('fs')
const { Certificate } = require('../src/index')

const issuer = Certificate.fromPEM(fs.readFileSync('./test/cert/github-issuer.crt'))

const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/github.crt'))
console.log(cert.isIssuer(issuer))
console.log(issuer.verify(cert))
console.log(issuer.verifySubjectKeyIdentifier())
console.log(cert.verifySubjectKeyIdentifier())
console.log(issuer)
console.log(cert)
