'use strict'
// **Github:** https://github.com/fidm/x509
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
    strictEqual(pems.length, 1)
    strictEqual(pems[0].type, 'CERTIFICATE')
  })
})
