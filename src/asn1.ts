'use strict'
// **Github:** https://github.com/fidm/x509js
//
// **License:** MIT

import { inspect } from 'util'
import { BufferVisitor, getOID } from './common'

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

  // Tag.BOOLEAN
  static Bool (val: boolean): ASN1 {
    return new ASN1(Class.UNIVERSAL, Tag.BOOLEAN, Buffer.from([val ? 0xff: 0x0]))
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

  // Tag.BOOLEAN
  static Integer (num: number): ASN1 {
    if (!Number.isSafeInteger(num)) {
      throw new Error('ASN1 syntax error: invalid integer')
    }
    let buf
    if(num >= -0x80 && num < 0x80) {
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
      throw new Error('ASN1 syntax error: invalid integer')
    }
    return new ASN1(Class.UNIVERSAL, Tag.INTEGER, buf)
  }

  static parseInteger (buf: Buffer): number {
    if(buf.length === 0 || buf.length > 6) {
      throw new Error('ASN1 syntax error: invalid integer')
    }
    return buf.readIntBE(0, buf.length)
  }

  // Tag.BITSTRING
  // BitString is the structure to use when you want an ASN.1 BIT STRING type. A
  // bit string is padded up to the nearest byte in memory and the number of
  // valid bits is recorded. Padding bits will be zero.
  // TODO

  // Tag.NULL
  static Null (): ASN1 {
    return new ASN1(Class.UNIVERSAL, Tag.NULL, Buffer.alloc(1))
  }

  static parseNull (buf: Buffer): null {
    if(buf.length !== 1 || buf.readInt8(0) !== 0) {
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
    let last, valueBytes, value, b
    for(var i = 2; i < values.length; ++i) {
      // produce value bytes in reverse because we don't know how many
      // bytes it will take to store the value
      last = true
      valueBytes = []
      value = parseInt(values[i], 10)
      do {
        b = value & 0x7F
        value = value >>> 7
        // if value is not last, then turn on 8th bit
        if(!last) {
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

    return new ASN1(Class.UNIVERSAL, Tag.OID, Buffer.from(bytes))
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
      if (b & 0x80) {
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
    return new ASN1(Class.UNIVERSAL, Tag.UTF8, Buffer.from(str, 'utf8'))
  }

  static parseUTF8 (buf: Buffer): string {
    return buf.toString('utf8')
  }

  // Tag.NUMERICSTRING
  static NumericString (str: string): ASN1 {
    if (!NumericReg.test(str)) {
      throw new Error('ASN1 syntax error: invalid NumericString')
    }
    return new ASN1(Class.UNIVERSAL, Tag.NUMERICSTRING, Buffer.from(str, 'utf8'))
  }

  static parseNumericString (buf: Buffer): string {
    for (const val of buf.values()) {
      if (!isNumeric(val)) {
        throw new Error('ASN1 syntax error: invalid NumericString')
      }
    }
    return buf.toString('utf8')
  }

  // Tag.PRINTABLESTRING
  static PrintableString (str: string): ASN1 {
    // TODO, validate
    return new ASN1(Class.UNIVERSAL, Tag.PRINTABLESTRING, Buffer.from(str, 'utf8'))
  }

  static parsePrintableString (buf: Buffer): string {
    // TODO, validate
    return buf.toString('utf8')
  }

  // Tag.IA5STRING, ASN.1 IA5String (ASCII string)
  static IA5String (str: string): ASN1 {
    // TODO, validate
    return new ASN1(Class.UNIVERSAL, Tag.IA5STRING, Buffer.from(str, 'utf8'))
  }

  static parseIA5String (buf: Buffer): string {
    // TODO, validate
    return buf.toString('utf8')
  }

  // Tag.T61STRING, ASN.1 T61String (8-bit clean string)
  static T61String (str: string): ASN1 {
    // TODO, validate
    return new ASN1(Class.UNIVERSAL, Tag.T61STRING, Buffer.from(str, 'utf8'))
  }

  static parseT61String (buf: Buffer): string {
    // TODO, validate
    return buf.toString('utf8')
  }

  // Tag.GENERALSTRING, ASN.1 GeneralString (specified in ISO-2022/ECMA-35)
  static GeneralString (str: string): ASN1 {
    // TODO, validate
    return new ASN1(Class.UNIVERSAL, Tag.GENERALSTRING, Buffer.from(str, 'utf8'))
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
    for (let i = 0; i < format.length; ++i) {
      if (format[i].length < 2) {
        rval += '0'
      }
      rval += format[i]
    }
    rval += 'Z'
    return new ASN1(Class.UNIVERSAL, Tag.UTCTIME, Buffer.from(rval, 'utf8'))
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
    let MM = parseInt(utc.substr(2, 2), 10) - 1 // use 0-11 for month
    let DD = parseInt(utc.substr(4, 2), 10)
    let hh = parseInt(utc.substr(6, 2), 10)
    let mm = parseInt(utc.substr(8, 2), 10)
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
        let hhoffset = parseInt(utc.substr(end + 1, 2), 10)
        let mmoffset = parseInt(utc.substr(end + 4, 2), 10)

        // calculate offset in milliseconds
        let offset = hhoffset * 60 + mmoffset
        offset *= 60000

        // apply offset
        if(c === '+') {
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
    for (var i = 0; i < format.length; ++i) {
      if(format[i].length < 2) {
        rval += '0'
      }
      rval += format[i]
    }
    rval += 'Z'
    return new ASN1(Class.UNIVERSAL, Tag.GENERALIZEDTIME, Buffer.from(rval, 'utf8'))
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

    let YYYY = parseInt(gentime.substr(0, 4), 10)
    let MM = parseInt(gentime.substr(4, 2), 10) - 1 // use 0-11 for month
    let DD = parseInt(gentime.substr(6, 2), 10)
    let hh = parseInt(gentime.substr(8, 2), 10)
    let mm = parseInt(gentime.substr(10, 2), 10)
    let ss = parseInt(gentime.substr(12, 2), 10)
    let fff = 0
    let offset = 0
    let isUTC = false

    if (gentime.charAt(gentime.length - 1) === 'Z') {
      isUTC = true
    }

    let end = gentime.length - 5, c = gentime.charAt(end)
    if (c === '+' || c === '-') {
      // get hours+minutes offset
      let hhoffset = parseInt(gentime.substr(end + 1, 2), 10)
      let mmoffset = parseInt(gentime.substr(end + 4, 2), 10)

      // calculate offset in milliseconds
      offset = hhoffset * 60 + mmoffset
      offset *= 60000

      // apply offset
      if(c === '+') {
        offset *= -1
      }

      isUTC = true
    }

    // check for second fraction
    if (gentime.charAt(14) === '.') {
      fff = parseFloat(gentime.substr(14)) * 1000
    }

    if(isUTC) {
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

  /**
   * Parses an asn1 object from a byte buffer in DER format.
   *
   * @param bytes the byte buffer to parse from.
   * @param [options] object with options or boolean strict flag
   *          [strict] true to be strict when checking value lengths, false to
   *            allow truncated values (default: true).
   *
   * @return the parsed asn1 object.
   */
  static fromDER (buf: Buffer, options: any = { strict: true }) {
    if (options.strict == null) {
      options.strict = true
    }

    return fromDER(new BufferVisitor(buf), 0, options)
  }

  /**
   * Validates that the given ASN.1 object is at least a super set of the
   * given ASN.1 structure. Only tag classes and types are checked. An
   * optional map may also be provided to capture ASN.1 values while the
   * structure is checked.
   *
   * To capture an ASN.1 value, set an object in the validator's 'capture'
   * parameter to the key to use in the capture map. To capture the full
   * ASN.1 object, specify 'captureAsn1'. To capture BIT STRING bytes, including
   * the leading unused bits counter byte, specify 'captureBitStringContents'.
   * To capture BIT STRING bytes, without the leading unused bits counter byte,
   * specify 'captureBitStringValue'.
   *
   * Objects in the validator may set a field 'optional' to true to indicate
   * that it isn't necessary to pass validation.
   *
   * @param obj the ASN.1 object to validate.
   * @param v the ASN.1 structure validator.
   * @param capture an optional map to capture values in.
   * @param errors an optional array for storing validation errors.
   *
   * @return true on success, false on failure.
   */
  static validate (obj: any, v: any, capture: any, errors?: any[]): boolean {
    let rval = false

    // ensure tag class and type are the same if specified
    if ((obj.class === v.class || typeof(v.class) === 'undefined') &&
      (obj.tag === v.tag || typeof(v.tag) === 'undefined')) {
      // ensure constructed flag is the same if specified
      if (obj.constructed === v.constructed ||
        typeof(v.constructed) === 'undefined') {
        rval = true

        // handle sub values
        if (v.value && Array.isArray(v.value)) {
          let j = 0
          for (let i = 0; rval && i < v.value.length; ++i) {
            rval = v.value[i].optional || false
            if (obj.value[j]) {
              rval = ASN1.validate(obj.value[j], v.value[i], capture, errors)
              if (rval) {
                ++j
              } else if (v.value[i].optional) {
                rval = true
              }
            }
            if (!rval && errors) {
              errors.push(
                '[' + v.name + '] ' +
                'Tag class "' + v.class + '", type "' +
                v.tag + '" expected value length "' +
                v.value.length + '", got "' + obj.value.length + '"')
            }
          }
        }

        if (rval && capture) {
          if (v.capture) {
            capture[v.capture] = obj.value
          }
          if (v.captureAsn1) {
            capture[v.captureAsn1] = obj
          }
          if (v.captureBitStringContents && obj.bitStringContents != null) {
            capture[v.captureBitStringContents] = obj.bitStringContents
          }
          if(v.captureBitStringValue && obj.bitStringContents != null) {
            if (obj.bitStringContents.length < 2) {
              capture[v.captureBitStringValue] = ''
            } else {
              // FIXME: support unused bits with data shifting
              let unused = obj.bitStringContents.charCodeAt(0)
              if (unused !== 0) {
                throw new Error('captureBitStringValue only supported for zero unused bits')
              }
              capture[v.captureBitStringValue] = obj.bitStringContents.slice(1)
            }
          }
        }
      } else if (errors) {
        errors.push(
          '[' + v.name + '] ' +
          'Expected constructed "' + v.constructed + '", got "' +
          obj.constructed + '"')
      }
    } else if (errors) {
      if(obj.class !== v.class) {
        errors.push(
          '[' + v.name + '] ' +
          'Expected tag class "' + v.class + '", got "' +
          obj.class + '"')
      }
      if (obj.tag !== v.tag) {
        errors.push(
          '[' + v.name + '] ' +
          'Expected type "' + v.tag + '", got "' + obj.tag + '"')
      }
    }
    return rval
  }

  /**
   * Creates a new asn1 object.
   *
   * @param tagClass the tag class for the object.
   * @param type the data type (tag number) for the object.
   * @param constructed true if the asn1 object is in constructed form.
   * @param value the value for the object, if it is not constructed.
   * @param [options] the options to use:
   *          [bitStringContents] the plain BIT STRING content including padding
   *            byte.
   *
   * @return the asn1 object.
   */
  class: Class
  tag: Tag
  value: Buffer | ASN1[]
  isCompound: boolean
  constructor (tagClass: Class, type: Tag, value: Buffer | ASN1[]) {
    // remove undefined values
    if (Array.isArray(value)) {
      value = value.filter((val) => val != null)
    }

    this.class = tagClass
    this.tag = type
    this.isCompound = Array.isArray(value)
    this.value = value
  }

  equals (obj: ASN1): boolean {
    if (!(obj instanceof ASN1)) {
      return false
    }
    if (this.class !== obj.class || this.tag !== obj.tag || this.isCompound !== obj.isCompound) {
      return false
    }
    if (typeof this.value !== typeof obj.value) {
      return false
    }
    if (this.value instanceof Buffer) {
      return this.value.equals(obj.value as Buffer)
    } else {
      const values = this.value as ASN1[]
      for (let i = 0; i< values.length; i++) {
        if (!values[i].equals(obj.value[i] as ASN1)) {
          return false
        }
      }
    }
    return true
  }

  byteLen (): number {
    let valueLen = 0
    if (this.isCompound) {
      const values = this.value as ASN1[]
      for (const val of values) {
        valueLen += val.byteLen()
      }
    } else {
      valueLen += this.value.length
    }
    if (valueLen <= 127) {
      return 1 + 1 + valueLen
    }
    return valueLen
  }

  // Converts the given asn1 object to a buffer of bytes in DER format.
  toDER (): Buffer {
    // build the first byte
    let b1 = this.class | this.tag
    // for storing the ASN.1 value
    let valueBuf = this.value as Buffer

    if (this.isCompound) {
      b1 |= 0x20
      // add all of the child DER bytes together
      const values = this.value as ASN1[]
      valueBuf = Buffer.concat(values.map((val) => val.toDER()))
    }

    let valueByteLen = 0 // use "short form" encoding
    if (valueBuf.length > 127) {
      // use "long form" encoding
      if (valueBuf.length <= 0xff) {
        valueByteLen += 1
      } else if (valueBuf.length <= 0xff) {
        valueByteLen += 1
      } else if (valueBuf.length <= 0xffff) {
        valueByteLen += 2
      } else if (valueBuf.length <= 0xffffff) {
        valueByteLen += 3
      } else if (valueBuf.length <= 0xffffffff) {
        valueByteLen += 4
      } else if (valueBuf.length <= 0xffffffffff) {
        valueByteLen += 5
      } else if (valueBuf.length <= 0xffffffffffff) {
        valueByteLen += 6
      } else {
        throw new Error('invalid value length')
      }
    }

    const buf = Buffer.allocUnsafe(2 + valueByteLen + valueBuf.length)
    buf.writeInt8(b1, 0)
    if (valueByteLen === 1) {
      buf.writeUInt8(valueBuf.length, 1)
      valueBuf.copy(buf, 2)
    } else {
      buf.writeUInt8(valueByteLen, 1)
      buf.writeUIntBE(valueBuf.length, 2, valueByteLen)
      valueBuf.copy(buf, 2 + valueByteLen)
    }

    return buf
  }

  valueOf (): any {
    if (this.isCompound) {
      return (this.value as ASN1[]).map((val) => val.toJSON())
    }

    const value = this.value as Buffer
    switch (this.tag) {
    case Tag.BOOLEAN:
      return ASN1.parseBool(value)
    case Tag.INTEGER:
      return ASN1.parseInteger(value)
    case Tag.NULL:
      return ASN1.parseNull(value)
    case Tag.OID:
      const oid = ASN1.parseOID(value)
      const name = getOID(oid)
      return name === '' ? oid : name
    case Tag.UTF8:
      return ASN1.parseUTF8(value)
    case Tag.NUMERICSTRING:
      return ASN1.parseNumericString(value)
    case Tag.PRINTABLESTRING:
      return ASN1.parsePrintableString(value)
    case Tag.T61STRING:
      return ASN1.parseT61String(value)
    case Tag.IA5STRING:
      return ASN1.parseIA5String(value)
    case Tag.GENERALSTRING:
      return ASN1.parseGeneralString(value)
    case Tag.UTCTIME:
      return ASN1.parseUTCTime(value)
    case Tag.GENERALIZEDTIME:
      return ASN1.parseGeneralizedTime(value)

    default:
      return value.toString('hex')
    }
  }

  toString (): string {
    return JSON.stringify(this.toJSON())
  }

  [inspect.custom] (_depth: any, _options: any): string {
    return `<${this.constructor.name} ${this.toString()}>`
  }

  toJSON () {
    return {
      class: Class[this.class],
      tag: Tag[this.tag],
      value: this.valueOf(),
    }
  }
}

// Gets the length of a BER-encoded ASN.1 value.
function _getValueLength (bufv: BufferVisitor): number {
  bufv.assertWalk(1, 'Too few bytes to read ASN.1 value length.')
  const byte = bufv.buf[bufv.start]

  // see if the length is "short form" or "long form" (bit 8 set)
  if ((byte & 0x80) === 0) {
    // if byte is 0, means asn1 object of indefinite length
    return byte
  }

  let byteLen = byte & 0x7f
  bufv.assertWalk(byteLen, 'Too few bytes to read ASN.1 value length.')
  return bufv.buf.readUIntBE(bufv.start, byteLen)
}

// Internal function to parse an asn1 object from a byte buffer in DER format.
function fromDER (bufv: BufferVisitor, depth: number, options: any): ASN1 {
  bufv.assertWalk(1, 'Too few bytes to read ASN.1 tag.')

  const b1 = bufv.buf[bufv.start]
  const tagClass = b1 & 0xc0
  const type = b1 & 0x1f

  // value storage
  let value = null
  let valueLen = _getValueLength(bufv)
  bufv.assertRemaining(valueLen)

  // constructed flag is bit 6 (32 = 0x20) of the first byte
  const isCompound = ((b1 & 0x20) === 0x20)
  if (isCompound) {
    // parse child asn1 objects from the value
    value = []
    if (valueLen == 0) {
      if (options.strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.')
      }
      // asn1 object of indefinite length, read until end tag
      for (;;) {
        bufv.assertRemaining(2)
        if (bufv.buf[bufv.start] === 0 && bufv.buf[bufv.start + 1] === 0) {
          break
        }
        value.push(fromDER(bufv, depth + 1, options))
      }
    } else {
      let readByteLen = 0
      while (readByteLen < valueLen) {
        const start = bufv.end
        value.push(fromDER(bufv, depth + 1, options))
        readByteLen += bufv.end - start
      }
    }

  } else {
    // asn1 not constructed or isCompound, get raw value
    if (valueLen === 0) {
      if (options.strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.')
      }
    }

    bufv.assertWalk(valueLen)
    value = bufv.buf.slice(bufv.start, bufv.end)
  }

  // create and return asn1 object
  return new ASN1(tagClass, type, value)
}

const NumericReg = /^[0-9 ]+$/
function isNumeric (b: number): boolean {
	return 48 <= b && b <= 57 || b == 32 // '0' to '9', and ' '
}
