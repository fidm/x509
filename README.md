# x509
X509 certificate tools for Node.js, includes PEM, ASN1 with DER.

## example

```js
const fs = require('fs')
const { PEM, ASN1 } = require('@fidm/x509')

const crtData = fs.readFileSync('./test/cert/github.crt')
const blocks = PEM.parse(crtData)
const asn1 = ASN1.fromDER(blocks[0].body, true)
console.log(asn1)
```
