'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, ok } from 'assert'
import { suite, it } from 'tman'
import { Certificate, Attribute } from '../src/x509'

const crtData = fs.readFileSync('./test/cert/github.crt')

suite('X509', function () {
  it('should work', function () {
    const cert = Certificate.fromPEM(crtData)
    console.log(cert.toJSON())
    const attr = cert.subject.getField('CN') as Attribute
    ok(attr != null)
    strictEqual(attr.value, 'github.com')
  })
})
