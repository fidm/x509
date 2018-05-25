'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, ok, throws } from 'assert'
import { suite, it } from 'tman'
import { PEM } from '../src/pem'

suite('PEM', function () {
  it('should work', function () {
    const crtData = fs.readFileSync('./test/cert/github.crt')
    const pems = PEM.parse(crtData)
    strictEqual(pems.length, 1)
    strictEqual(pems[0].type, 'CERTIFICATE')
    strictEqual(pems[0].procType, '')
    strictEqual(pems[0].getHeader('DEK-Info'), '')
    strictEqual(pems[0].toString(), crtData.toString())
    ok(pems[0].body instanceof Buffer)
  })

  it('should throw error if no block', function () {
    throws(() => PEM.parse(Buffer.alloc(0)))
  })
})
