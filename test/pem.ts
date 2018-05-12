'use strict'
// **Github:** https://github.com/fidm/x509js
//
// **License:** MIT

import fs from 'fs'
import { strictEqual } from 'assert'
import { suite, it } from 'tman'
import { PEM } from '../src/pem'

const crtData = fs.readFileSync('./test/cert/github.crt')

suite('PEM', function () {
  it('should work', function () {
    const pems = PEM.parse(crtData)
    strictEqual(pems.length, 2)
    strictEqual(pems[0].type, 'CERTIFICATE')
    strictEqual(pems[1].type, 'CERTIFICATE')
    strictEqual(pems[0].toString() + pems[1].toString(), crtData.toString('utf8'))
  })
})
