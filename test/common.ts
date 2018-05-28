'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { strictEqual, ok } from 'assert'
import { suite, it } from 'tman'
import { bytesFromIP, bytesToIP, getOID, getOIDName } from '../src/index'

suite('common', function () {
  it('bytesFromIP', function () {
    strictEqual(bytesFromIP('.1.1.1'), null)
    strictEqual(bytesFromIP('a.1.1.1'), null)
    ok(Buffer.from([1, 1, 1, 1]).equals(bytesFromIP('1.1.1.1') as Buffer))
    ok(Buffer.from([127, 0, 0, 1]).equals(bytesFromIP('127.0.0.1') as Buffer))
    ok(Buffer.from([0, 0, 0, 0]).equals(bytesFromIP('0.0.0.0') as Buffer))

    strictEqual(bytesFromIP('xyz::1'), null)
    strictEqual(bytesFromIP('2001::25de::cade'), null)
    ok(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      .equals(bytesFromIP('::') as Buffer))
    ok(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      .equals(bytesFromIP('::0') as Buffer))
    ok(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      .equals(bytesFromIP('0::') as Buffer))
    ok(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
      .equals(bytesFromIP('::1') as Buffer))
    ok(Buffer.from([0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      .equals(bytesFromIP('1::0') as Buffer))
    ok(Buffer.from([0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      .equals(bytesFromIP('ff01::') as Buffer))
    ok(Buffer.from([0, 0, 0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0xff, 0, 0])
      .equals(bytesFromIP('0:ff01::0:ff:ff:0') as Buffer))
    ok(Buffer.from([0, 0, 0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0xff, 0, 0])
      .equals(bytesFromIP('0:ff01::ff:ff:0') as Buffer))
    ok(Buffer.from([0xf, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1])
      .equals(bytesFromIP('f01:0:0:1::1') as Buffer))
    ok(Buffer.from([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x28, 0x57, 0xab])
      .equals(bytesFromIP('2001:0db8::1428:57ab') as Buffer))
  })

  it('bytesToIP', function () {
    strictEqual(bytesToIP(Buffer.from([1, 1, 1, 1])), '1.1.1.1')
    strictEqual(bytesToIP(Buffer.from([127, 0, 0, 1])), '127.0.0.1')
    strictEqual(bytesToIP(Buffer.from([0, 0, 0, 0])), '0.0.0.0')

    strictEqual(bytesToIP(
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])), '::')
    strictEqual(bytesToIP(
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])), '::1')
    strictEqual(bytesToIP(
      Buffer.from([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])), '1::')
    strictEqual(bytesToIP(
        Buffer.from([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])), '1::1')
    strictEqual(bytesToIP(
      Buffer.from([0xff, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])), 'ff01::')
    strictEqual(bytesToIP(
      Buffer.from([0xff, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0])), 'ff01::100')
    strictEqual(bytesToIP(
      Buffer.from([0, 0, 0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0xff, 0, 0])), '0:ff01::ff:ff:0')
    strictEqual(bytesToIP(
      Buffer.from([0xf, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1])), 'f01:0:0:1::1')
  })

  it('getOID', function () {
    strictEqual(getOID('1.2.840.113549.1.1.1'), '1.2.840.113549.1.1.1')
    strictEqual(getOID('rsaEncryption'), '1.2.840.113549.1.1.1')
    strictEqual(getOID('rsaEncryptionx'), '')
  })

  it('getOIDName', function () {
    strictEqual(getOIDName('1.2.840.113549.1.1.1'), 'rsaEncryption')
    strictEqual(getOIDName('rsaEncryption'), 'rsaEncryption')
    strictEqual(getOIDName('rsaEncryptionx'), 'rsaEncryptionx')
    strictEqual(getOIDName('1.2.3.4.5.6.7.8.9.0'), '1.2.3.4.5.6.7.8.9.0')
  })
})
