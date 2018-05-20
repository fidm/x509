'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, ok } from 'assert'
import { suite, it } from 'tman'
import { PEM } from '../src/pem'
import { ASN1, Class, Tag } from '../src/asn1'

const crtData = fs.readFileSync('./test/cert/github.crt')

suite('ASN1', function () {
  const blocks = PEM.parse(crtData)

  it('should work', function () {
    const asn1 = ASN1.fromDER(blocks[0].body, true)
    strictEqual(asn1.class, Class.UNIVERSAL)
    strictEqual(asn1.tag, Tag.SEQUENCE)
    ok(Array.isArray(asn1.value))
    ok(asn1.toString().includes('github.com'))
  })
})
