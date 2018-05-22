'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

require('ts-node/register')
const fs = require('fs')
const { Certificate } = require('../src/index')

const rootcert = Certificate.fromPEM(fs.readFileSync('./test/cert/github.crt'))

const cert = Certificate.fromPEM(fs.readFileSync('./test/cert/test.crt'))
console.log(cert.isIssuer(rootcert))
console.log(rootcert.verify(cert))
console.log(rootcert.verifySubjectKeyIdentifier())
console.log(cert.verifySubjectKeyIdentifier())
console.log(rootcert)
console.log(cert)
