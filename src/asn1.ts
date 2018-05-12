'use strict'
// **Github:** https://github.com/fidm/x509js
//
// **License:** MIT

import { inspect } from 'util'
import { BufferVisitor, getOID, getOIDName } from './common'

export interface Template {
  name?: string
  class: Class
  tag: Tag
  optional?: boolean
  capture?: string
  value?: Template[]
}

export interface Captures {
  [index: string]: ASN1
}

// ASN.1 classes.
export enum Class {
  UNIVERSAL = 0x00,
  APPLICATION = 0x40,
  CONTEXT_SPECIFIC = 0x80,
  PRIVATE = 0xC0,
}

// ASN.1 types. Not all types are supported by this implementation
export enum Tag {
  NONE = 0,
  BOOLEAN = 1,
  INTEGER = 2,
  BITSTRING = 3,
  OCTETSTRING = 4,
  NULL = 5,
  OID = 6,
  // ODESC = 7,
  // EXTERNAL = 8,
  // REAL = 9,
  ENUMERATED = 10,
  // EMBEDDED = 11,
  UTF8 = 12,
  // ROID = 13,
  SEQUENCE = 16,
  SET = 17,
  NUMERICSTRING = 18,
  PRINTABLESTRING = 19,
  T61STRING = 20,
  IA5STRING = 22,
  UTCTIME = 23,
  GENERALIZEDTIME = 24,
  GENERALSTRING = 27,
}

export class BitString {
  buf: Buffer
  bitLen: number
  constructor (buf: Buffer, bitLen: number) {
    this.buf = buf
    this.bitLen = bitLen
  }

  at (i: number): number {
    if (i < 0 || i >= this.bitLen || !Number.isInteger(i)) {
      return 0
    }
    const x = Math.floor(i / 8)
    const y = 7 - i % 8
    return (this.buf[x] >> y) & 1
  }

  rightAlign (): Buffer {
    const shift = 8 - (this.bitLen % 8)
    if (shift === 8 || this.buf.length === 0) {
      return this.buf
    }

    const buf = Buffer.alloc(this.buf.length)
    buf[0] = this.buf[0] >> shift
    for (let i = 1; i < this.buf.length; i++) {
      buf[i] = this.buf[i - 1] << (8 - shift)
      buf[i] |= this.buf[i] >> shift
    }
    return buf
  }
}

// Implements parsing of DER-encoded ASN.1 data structures,
// as defined in ITU-T Rec X.690.
//
// See also ``A Layman's Guide to a Subset of ASN.1, BER, and DER,''
// http://luca.ntop.org/Teaching/Appunti/asn1.html.
//
// ASN.1 is a syntax for specifying abstract objects and BER, DER, PER, XER etc
// are different encoding formats for those objects. Here, we'll be dealing
// with DER, the Distinguished Encoding Rules. DER is used in X.509 because
// it's fast to parse and, unlike BER, has a unique encoding for every object.
// When calculating hashes over objects, it's important that the resulting
// bytes be the same at both ends and DER removes this margin of error.
//
// ASN.1 is very complex and this package doesn't attempt to implement
// everything by any means.
export class ASN1 {

  // DER Encoding of ASN.1 Types
  // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540792(v=vs.85).aspx
  // Tag.BOOLEAN
  static Bool (val: boolean): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.BOOLEAN, Buffer.from([val ? 0xff : 0x0]))
    asn1._value = val
    return asn1
  }

  static parseBool (buf: Buffer): boolean {
    if (buf.length !== 1) {
      throw new Error('ASN1 syntax error: invalid boolean')
    }
    switch (buf[0]) {
    case 0:
      return false
    case 0xff:
      return true
    default:
      throw new Error('ASN1 syntax error: invalid boolean')
    }
  }

  // Tag.INTEGER
  static Integer (num: number | Buffer): ASN1 {
    if (num instanceof Buffer) {
      const asn = new ASN1(Class.UNIVERSAL, Tag.INTEGER, num)
      asn._value = '0x' + num.toString('hex')
      return asn
    }

    if (!Number.isSafeInteger(num)) {
      throw new Error('ASN1 syntax error: invalid integer')
    }
    let buf
    if (num >= -0x80 && num < 0x80) {
      buf = Buffer.alloc(1)
      buf.writeInt8(num, 0)
    } else if (num >= -0x8000 && num < 0x8000) {
      buf = Buffer.alloc(2)
      buf.writeIntBE(num, 0, 2)
    } else if (num >= -0x800000 && num < 0x800000) {
      buf = Buffer.alloc(3)
      buf.writeIntBE(num, 0, 3)
    } else if (num >= -0x80000000 && num < 0x80000000) {
      buf = Buffer.alloc(4)
      buf.writeIntBE(num, 0, 4)
    } else if (num >= -0x8000000000 && num < 0x8000000000) {
      buf = Buffer.alloc(5)
      buf.writeIntBE(num, 0, 5)
    } else if (num >= -0x800000000000 && num < 0x800000000000) {
      buf = Buffer.alloc(6)
      buf.writeIntBE(num, 0, 6)
    } else {
      throw new Error('ASN1 syntax error: invalid Integer')
    }
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.INTEGER, buf)
    asn1._value = num
    return asn1
  }

  static parseInteger (buf: Buffer): number | string {
    if (buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid Integer')
    }
    // some INTEGER will be 16 bytes, 32 bytes or others.
    // CertificateSerialNumber ::= INTEGER (>= 16 bytes)
    if (buf.length > 6) {
      return '0x' + buf.toString('hex')
    }
    return buf.readIntBE(0, buf.length)
  }

  // Tag.BITSTRING
  // BitString is the structure to use when you want an ASN.1 BIT STRING type. A
  // bit string is padded up to the nearest byte in memory and the number of
  // valid bits is recorded. Padding bits will be zero.
  static parseBitString (buf: Buffer): BitString {
    if (buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid BitString')
    }

    const paddingBits = buf[0]
    if (paddingBits > 7 ||
      buf.length === 1 && paddingBits > 0 ||
      (buf[buf.length - 1] & ((1 << buf[0]) - 1)) !== 0) {
      throw new Error('ASN1 syntax error: invalid padding bits in BIT STRING')
    }

    return new BitString(buf.slice(1), (buf.length - 1) * 8 - paddingBits)
  }

  // Tag.NULL
  static Null (): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.NULL, Buffer.alloc(0))
    asn1._value = null
    return asn1
  }

  static parseNull (buf: Buffer): null {
    if (buf.length !== 0) {
      throw new Error('ASN1 syntax error: invalid null')
    }
    return null
  }

  // Tag.OID
  // Converts an OID dot-separated string to a byte buffer.
  static OID (oid: string): ASN1 {
    oid = getOID(oid)
    if (oid === '') {
      throw new Error('ASN1 syntax error: invalid ObjectIdentifier')
    }

    const values = oid.split('.')
    const bytes: number[] = []

    // first byte is 40 * value1 + value2
    bytes.push(40 * parseInt(values[0], 10) + parseInt(values[1], 10))
    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    let last
    let valueBytes
    let value
    let b
    for (let i = 2; i < values.length; ++i) {
      // produce value bytes in reverse because we don't know how many
      // bytes it will take to store the value
      last = true
      valueBytes = []
      value = parseInt(values[i], 10)
      do {
        b = value & 0x7F
        value = value >>> 7
        // if value is not last, then turn on 8th bit
        if (!last) {
          b |= 0x80
        }
        valueBytes.push(b)
        last = false
      } while (value > 0)

      // add value bytes in reverse (needs to be in big endian)
      for (let n = valueBytes.length - 1; n >= 0; --n) {
        bytes.push(valueBytes[n])
      }
    }

    const asn1 = new ASN1(Class.UNIVERSAL, Tag.OID, Buffer.from(bytes))
    asn1._value = oid
    return asn1
  }

  static parseOID (buf: Buffer): string {
    // first byte is 40 * value1 + value2
    let b = buf[0]
    let oid = Math.floor(b / 40) + '.' + (b % 40)

    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    let value = 0
    for (let i = 1; i < buf.length; i++) {
      b = buf[i]
      value = value << 7
      // not the last byte for the value
      if ((b & 0x80) === 0x80) {
        value += b & 0x7F
      } else {
        // last byte
        oid += '.' + (value + b)
        value = 0
      }
    }

    return oid
  }

  // Tag.ENUMERATED
  // An Enumerated is represented as a plain int.
  // TODO

  // Tag.UTF8
  static UTF8 (str: string): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.UTF8, Buffer.from(str, 'utf8'))
    asn1._value = str
    return asn1
  }

  static parseUTF8 (buf: Buffer): string {
    return buf.toString('utf8')
  }

  // Tag.NUMERICSTRING
  static NumericString (str: string): ASN1 {
    if (!isNumericString(str)) {
      throw new Error('ASN1 syntax error: invalid NumericString')
    }
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.NUMERICSTRING, Buffer.from(str, 'utf8'))
    asn1._value = str
    return asn1
  }

  static parseNumericString (buf: Buffer): string {
    const str = buf.toString('utf8')
    if (!isNumericString(str)) {
      throw new Error('ASN1 syntax error: invalid NumericString')
    }
    return str
  }

  // Tag.PRINTABLESTRING
  static PrintableString (str: string): ASN1 {
    // TODO, validate
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.PRINTABLESTRING, Buffer.from(str, 'utf8'))
    asn1._value = str
    return asn1
  }

  static parsePrintableString (buf: Buffer): string {
    // TODO, validate
    return buf.toString('utf8')
  }

  // Tag.IA5STRING, ASN.1 IA5String (ASCII string)
  static IA5String (str: string): ASN1 {
    if (!isIA5String(str)) {
      throw new Error('ASN1 syntax error: invalid IA5String')
    }
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.IA5STRING, Buffer.from(str, 'utf8'))
    asn1._value = str
    return asn1
  }

  static parseIA5String (buf: Buffer): string {
    const str = buf.toString('utf8')
    if (!isIA5String(str)) {
      throw new Error('ASN1 syntax error: invalid IA5String')
    }
    return str
  }

  // Tag.T61STRING, ASN.1 T61String (8-bit clean string)
  static T61String (str: string): ASN1 {
    // TODO, validate
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.T61STRING, Buffer.from(str, 'utf8'))
    asn1._value = str
    return asn1
  }

  static parseT61String (buf: Buffer): string {
    // TODO, validate
    return buf.toString('utf8')
  }

  // Tag.GENERALSTRING, ASN.1 GeneralString (specified in ISO-2022/ECMA-35)
  static GeneralString (str: string): ASN1 {
    // TODO, validate
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.GENERALSTRING, Buffer.from(str, 'utf8'))
    asn1._value = str
    return asn1
  }

  static parseGeneralString (buf: Buffer): string {
    // TODO, validate
    return buf.toString('utf8')
  }

  // Tag.UTCTIME
  // Note: GeneralizedTime has 4 digits for the year and is used for X.509
  // dates past 2049. Converting to a GeneralizedTime hasn't been implemented yet.
  static UTCTime (date: Date): ASN1 {
    let rval = ''

    // create format YYMMDDhhmmssZ
    const format = []
    format.push(('' + date.getUTCFullYear()).substr(2))
    format.push('' + (date.getUTCMonth() + 1))
    format.push('' + date.getUTCDate())
    format.push('' + date.getUTCHours())
    format.push('' + date.getUTCMinutes())
    format.push('' + date.getUTCSeconds())

    // ensure 2 digits are used for each format entry
    for (const s of format) {
      if (s.length < 2) {
        rval += '0'
      }
      rval += s
    }
    rval += 'Z'
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.UTCTIME, Buffer.from(rval, 'utf8'))
    asn1._value = date
    return asn1
  }

  // Note: GeneralizedTime has 4 digits for the year and is used for X.509
  // dates past 2049. Parsing that structure hasn't been implemented yet.
  static parseUTCTime (buf: Buffer): Date {
    const utc = buf.toString('utf8')
    /* The following formats can be used:

      YYMMDDhhmmZ
      YYMMDDhhmm+hh'mm'
      YYMMDDhhmm-hh'mm'
      YYMMDDhhmmssZ
      YYMMDDhhmmss+hh'mm'
      YYMMDDhhmmss-hh'mm'

      Where:

      YY is the least significant two digits of the year
      MM is the month (01 to 12)
      DD is the day (01 to 31)
      hh is the hour (00 to 23)
      mm are the minutes (00 to 59)
      ss are the seconds (00 to 59)
      Z indicates that local time is GMT, + indicates that local time is
      later than GMT, and - indicates that local time is earlier than GMT
      hh' is the absolute value of the offset from GMT in hours
      mm' is the absolute value of the offset from GMT in minutes */
    const date = new Date()

    // if YY >= 50 use 19xx, if YY < 50 use 20xx
    let year = parseInt(utc.substr(0, 2), 10)
    year = (year >= 50) ? 1900 + year : 2000 + year
    const MM = parseInt(utc.substr(2, 2), 10) - 1 // use 0-11 for month
    const DD = parseInt(utc.substr(4, 2), 10)
    const hh = parseInt(utc.substr(6, 2), 10)
    const mm = parseInt(utc.substr(8, 2), 10)
    let ss = 0

    let end = 0
    // get character after minutes
    let c = ''
    // not just YYMMDDhhmmZ
    if (utc.length > 11) {
      end = 10
      // get character after minutes
      c = utc.charAt(end)
      // see if seconds are present
      if (c !== '+' && c !== '-') {
        // get seconds
        ss = parseInt(utc.substr(10, 2), 10)
        end += 2
      }
    }

    // update date
    date.setUTCFullYear(year, MM, DD)
    date.setUTCHours(hh, mm, ss, 0)

    if (end > 0) {
      // get +/- after end of time
      c = utc.charAt(end)
      if (c === '+' || c === '-') {
        // get hours+minutes offset
        const hhoffset = parseInt(utc.substr(end + 1, 2), 10)
        const mmoffset = parseInt(utc.substr(end + 4, 2), 10)

        // calculate offset in milliseconds
        let offset = hhoffset * 60 + mmoffset
        offset *= 60000

        // apply offset
        if (c === '+') {
          date.setTime(+date - offset)
        } else {
          date.setTime(+date + offset)
        }
      }
    }

    return date
  }

  // Tag.GENERALIZEDTIME
  static GeneralizedTime (date: Date): ASN1 {
    let rval = ''

    // create format YYYYMMDDHHMMSSZ
    const format = []
    format.push('' + date.getUTCFullYear())
    format.push('' + (date.getUTCMonth() + 1))
    format.push('' + date.getUTCDate())
    format.push('' + date.getUTCHours())
    format.push('' + date.getUTCMinutes())
    format.push('' + date.getUTCSeconds())

    // ensure 2 digits are used for each format entry
    for (const s of format) {
      if (s.length < 2) {
        rval += '0'
      }
      rval += s
    }
    rval += 'Z'
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.GENERALIZEDTIME, Buffer.from(rval, 'utf8'))
    asn1._value = date
    return asn1
  }

  // Converts a GeneralizedTime value to a date.
  static parseGeneralizedTime (buf: Buffer): Date {
    const gentime = buf.toString('utf8')
    /* The following formats can be used:

      YYYYMMDDHHMMSS
      YYYYMMDDHHMMSS.fff
      YYYYMMDDHHMMSSZ
      YYYYMMDDHHMMSS.fffZ
      YYYYMMDDHHMMSS+hh'mm'
      YYYYMMDDHHMMSS.fff+hh'mm'
      YYYYMMDDHHMMSS-hh'mm'
      YYYYMMDDHHMMSS.fff-hh'mm'

      Where:

      YYYY is the year
      MM is the month (01 to 12)
      DD is the day (01 to 31)
      hh is the hour (00 to 23)
      mm are the minutes (00 to 59)
      ss are the seconds (00 to 59)
      .fff is the second fraction, accurate to three decimal places
      Z indicates that local time is GMT, + indicates that local time is
      later than GMT, and - indicates that local time is earlier than GMT
      hh' is the absolute value of the offset from GMT in hours
      mm' is the absolute value of the offset from GMT in minutes */
    const date = new Date()

    const YYYY = parseInt(gentime.substr(0, 4), 10)
    const MM = parseInt(gentime.substr(4, 2), 10) - 1 // use 0-11 for month
    const DD = parseInt(gentime.substr(6, 2), 10)
    const hh = parseInt(gentime.substr(8, 2), 10)
    const mm = parseInt(gentime.substr(10, 2), 10)
    const ss = parseInt(gentime.substr(12, 2), 10)
    let fff = 0
    let offset = 0
    let isUTC = false

    if (gentime.charAt(gentime.length - 1) === 'Z') {
      isUTC = true
    }

    const end = gentime.length - 5
    const c = gentime.charAt(end)
    if (c === '+' || c === '-') {
      // get hours+minutes offset
      const hhoffset = parseInt(gentime.substr(end + 1, 2), 10)
      const mmoffset = parseInt(gentime.substr(end + 4, 2), 10)

      // calculate offset in milliseconds
      offset = hhoffset * 60 + mmoffset
      offset *= 60000

      // apply offset
      if (c === '+') {
        offset *= -1
      }

      isUTC = true
    }

    // check for second fraction
    if (gentime.charAt(14) === '.') {
      fff = parseFloat(gentime.substr(14)) * 1000
    }

    if (isUTC) {
      date.setUTCFullYear(YYYY, MM, DD)
      date.setUTCHours(hh, mm, ss, fff)
      // apply offset
      date.setTime(+date + offset)
    } else {
      date.setFullYear(YYYY, MM, DD)
      date.setHours(hh, mm, ss, fff)
    }

    return date
  }

  static Set (objs: ASN1[]): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.SET, Buffer.concat(objs.map((obj) => obj.toDER())))
    asn1._value = objs
    return asn1
  }

  static Seq (objs: ASN1[]): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.SEQUENCE, Buffer.concat(objs.map((obj) => obj.toDER())))
    asn1._value = objs
    return asn1
  }

  // Parses an asn1 object from a byte buffer in DER format.
  static fromDER (buf: Buffer, deepParse: boolean = false): ASN1 {
    return ASN1._fromDER(new BufferVisitor(buf), deepParse)
  }

  private static _parseCompound (buf: Buffer, deepParse: boolean): ASN1[] {
    const values = []
    const len = buf.length
    const bufv = new BufferVisitor(buf)
    let readByteLen = 0
    while (readByteLen < len) {
      const start = bufv.end
      values.push(ASN1._fromDER(bufv, deepParse))
      readByteLen += bufv.end - start
    }
    return values
  }

  // Internal function to parse an asn1 object from a byte buffer in DER format.
  private static _fromDER (bufv: BufferVisitor, deepParse: boolean): ASN1 {
    bufv.mustWalk(1, 'Too few bytes to read ASN.1 tag.')

    const b1 = bufv.buf[bufv.start]
    const tagClass = b1 & 0xc0
    const tag = b1 & 0x1f

    // value storage
    const valueLen = getValueLength(bufv)
    bufv.mustHas(valueLen)
    if (valueLen === 0 && tag !== Tag.NULL || (valueLen !== 0 && tag === Tag.NULL)) {
      throw new Error('invalid value length or NULL tag.')
    }

    bufv.mustWalk(valueLen)
    const isCompound = ((b1 & 0x20) === 0x20)
    const asn1 = new ASN1(tagClass, tag, bufv.buf.slice(bufv.start, bufv.end), isCompound)
    if (isCompound && deepParse) {
      asn1._value = ASN1._parseCompound(asn1.bytes, deepParse)
    }

    return asn1
  }

  class: Class
  tag: Tag
  bytes: Buffer
  isCompound: boolean
  private _value: any
  constructor (tagClass: Class, tag: Tag, data: Buffer, isCompound: boolean = false) {
    this.class = tagClass
    this.tag = tag
    this.bytes = data
    this.isCompound = isCompound || tag === Tag.SEQUENCE || tag === Tag.SET // SEQUENCE, SET, NONE, others...
    this._value = undefined
  }

  get value () {
    if (this._value === undefined) {
      this._value = this.valueOf()
    }
    return this._value
  }

  mustCompound (msg: string = 'asn1 object value is not compound'): ASN1[] {
    if (!this.isCompound || !Array.isArray(this.value)) {
      throw new Error(msg)
    }
    return this.value as ASN1[]
  }

  equals (obj: ASN1): boolean {
    if (!(obj instanceof ASN1)) {
      return false
    }
    if (this.class !== obj.class || this.tag !== obj.tag || this.isCompound !== obj.isCompound) {
      return false
    }
    if (!this.bytes.equals(obj.bytes)) {
      return false
    }
    return true
  }

  // Converts the given asn1 object to a buffer of bytes in DER format.
  toDER (): Buffer {
    // build the first byte
    let b1 = this.class | this.tag
    if (this.isCompound) {
      b1 |= 0x20
    }

    const valueLenBytes = getValueLengthByte(this.bytes.length)
    const buf = Buffer.allocUnsafe(2 + valueLenBytes + this.bytes.length)
    buf.writeInt8(b1, 0)
    if (valueLenBytes === 0) {
      buf.writeUInt8(this.bytes.length, 1)
      this.bytes.copy(buf, 2)
    } else {
      buf.writeUInt8(valueLenBytes, 1)
      buf.writeUIntBE(this.bytes.length, 2, valueLenBytes)
      this.bytes.copy(buf, 2 + valueLenBytes)
    }

    return buf
  }

  valueOf (): any {
    if (this.isCompound) {
      return ASN1._parseCompound(this.bytes, false)
    }

    switch (this.tag) {
    case Tag.BOOLEAN:
      return ASN1.parseBool(this.bytes)
    case Tag.INTEGER:
      return ASN1.parseInteger(this.bytes)
    case Tag.BITSTRING:
      return ASN1.parseBitString(this.bytes)
    case Tag.NULL:
      return ASN1.parseNull(this.bytes)
    case Tag.OID:
      const oid = ASN1.parseOID(this.bytes)
      const name = getOIDName(oid)
      return name === '' ? oid : name
    case Tag.UTF8:
      return ASN1.parseUTF8(this.bytes)
    case Tag.NUMERICSTRING:
      return ASN1.parseNumericString(this.bytes)
    case Tag.PRINTABLESTRING:
      return ASN1.parsePrintableString(this.bytes)
    case Tag.T61STRING:
      return ASN1.parseT61String(this.bytes)
    case Tag.IA5STRING:
      return ASN1.parseIA5String(this.bytes)
    case Tag.GENERALSTRING:
      return ASN1.parseGeneralString(this.bytes)
    case Tag.UTCTIME:
      return ASN1.parseUTCTime(this.bytes)
    case Tag.GENERALIZEDTIME:
      return ASN1.parseGeneralizedTime(this.bytes)

    default:
      return this.bytes
    }
  }

  /**
   * Validates that the given ASN.1 object is at least a super set of the
   * given ASN.1 structure. Only tag classes and types are checked. An
   * optional map may also be provided to capture ASN.1 values while the
   * structure is checked.
   *
   * To capture an ASN.1 value, set an object in the validator's 'capture'
   * parameter to the key to use in the capture map. To capture the full
   * ASN.1 object, specify 'captureASN1'.
   *
   * Objects in the validator may set a field 'optional' to true to indicate
   * that it isn't necessary to pass validation.
   *
   * @param tpl the ASN.1 structure Template.
   * @param capture an optional map to capture values in.
   *
   * @return null on success, Error on failure.
   */
  validate (tpl: Template, capture: Captures = {}): Error | null {
    if (this.class !== tpl.class) {
      return new Error(`ASN.1 object validate ${tpl.name}: error class`)
    }
    if (this.tag !== tpl.tag) {
      return new Error(`ASN.1 object validate ${tpl.name}: error tag`)
    }

    if (tpl.capture != null) {
      capture[tpl.capture] = this
    }

    if (Array.isArray(tpl.value)) {
      const values = this.mustCompound()
      for (let i = 0; i < tpl.value.length; i++) {
        const ret = values[i].validate(tpl.value[i], capture)
        if (ret != null && tpl.value[i].optional !== true) {
          return ret
        }
      }
    }

    return null
  }

  toString (): string {
    return JSON.stringify(this.toJSON())
  }

  toJSON () {
    let value = this.value
    if (Array.isArray(value)) {
      value = value.map((val) => val.toJSON())
    }
    return {
      class: Class[this.class],
      tag: Tag[this.tag],
      value,
    }
  }

  [inspect.custom] (_depth: any, _options: any): string {
    return `<${this.constructor.name} ${this.toString()}>`
  }
}

// Gets the length of a BER-encoded ASN.1 value.
function getValueLength (bufv: BufferVisitor): number {
  bufv.mustWalk(1, 'Too few bytes to read ASN.1 value length.')
  const byte = bufv.buf[bufv.start]

  // see if the length is "short form" or "long form" (bit 8 set)
  if ((byte & 0x80) === 0) {
    // if byte is 0, means asn1 object of indefinite length
    return byte
  }

  const byteLen = byte & 0x7f
  bufv.mustWalk(byteLen, 'Too few bytes to read ASN.1 value length.')
  return bufv.buf.readUIntBE(bufv.start, byteLen)
}

// Gets the length of a BER-encoded ASN.1 value length's bytes
function getValueLengthByte (valueLen: number): number {
  if (valueLen <= 127) {
    return 0
  } else if (valueLen <= 0xff) {
    return 1
  } else if (valueLen <= 0xffff) {
    return 2
  } else if (valueLen <= 0xffffff) {
    return 3
  } else if (valueLen <= 0xffffffff) {
    return 4
  } else if (valueLen <= 0xffffffffff) {
    return 5
  } else if (valueLen <= 0xffffffffffff) {
    return 6
  } else {
    throw new Error('invalid value length')
  }
}

function isNumericString (str: string): boolean {
  for (const s of str) {
    const n = s.charCodeAt(0)
    if (n !== 32 && (n < 48 || n > 57)) { // '0' to '9', and ' '
      return false
    }
  }
  return true
}

function isIA5String (str: string): boolean {
  for (const s of str) {
    if (s.charCodeAt(0) >= 0x80) {
      return false
    }
  }
  return true
}
