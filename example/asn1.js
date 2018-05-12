'use strict'
// **Github:** https://github.com/fidm/x509js
//
// **License:** MIT

const fs = require('fs')
const { PEM, ASN1 } = require('../')

const crtData = fs.readFileSync('./test/cert/github.crt')
const blocks = PEM.parse(crtData)
const asn1 = ASN1.fromDER(blocks[0].body, true)
console.log(asn1)

console.log(ASN1.fromDER(blocks[1].body, true))
