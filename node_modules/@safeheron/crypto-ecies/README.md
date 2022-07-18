# crypto-ecies-js

# Installation
```shell
npm install @safeheron/crypto-ecies --registry=https://npm.91aql.com
```

# Examples

## ECIES
- Encrypt a string
```javascript
        import * as cryptoJS from "crypto-js"
        import * as elliptic from 'elliptic'
        import * as assert from 'assert'
        import {Rand, Prime} from "@safeheron/crypto-rand"
        const P256 = elliptic.ec('p256')
        import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"
        import {ECIES, AuthEnc, Authorize} from "@safeheron/crypto-ecies"
        
        let priv = await Rand.randomBN(32)
        console.log('priv: ', priv.toString(16))
        let pub = P256.g.mul(priv)
        let msg = 'hello world'
        let cypher = await ECIES.encryptString(pub, msg)
        console.log("cypher: ", Hex.fromBytes(cypher))
        let plain = ECIES.decryptString(priv, cypher)
        console.log("plain: ", plain)
        assert.equal(msg, plain)
```

- Encrypt bytes
```javascript
        import * as cryptoJS from "crypto-js"
        import * as elliptic from 'elliptic'
        import * as assert from 'assert'
        import {Rand, Prime} from "@safeheron/crypto-rand"
        const P256 = elliptic.ec('p256')
        import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"
        import {ECIES, AuthEnc, Authorize} from "@safeheron/crypto-ecies"
        
        let priv = await Rand.randomBN(32)
        console.log('priv: ', priv.toString(16))
        let pub = P256.g.mul(priv)
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        let cypher = await ECIES.encryptBytes(pub, data)
        console.log('cypher: ', Hex.fromBytes(cypher))
        let plain = ECIES.decryptBytes(priv, cypher)
        console.log("plain data: ", Hex.fromBytes(plain))
        assert.equal(data.length, plain.length)
        for(let i = 0; i < data.length; i++){
            assert.equal(data.at(i), plain.at(i))
        }
```

- Encrypt CryptoJSBytes
```javascript
        import * as cryptoJS from "crypto-js"
        import * as elliptic from 'elliptic'
        import * as assert from 'assert'
        import {Rand, Prime} from "@safeheron/crypto-rand"
        const P256 = elliptic.ec('p256')
        import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"
        import {ECIES, AuthEnc, Authorize} from "@safeheron/crypto-ecies"
        
        
        let priv = await Rand.randomBN(32)
        console.log('priv: ', priv.toString(16))
        let pub = P256.g.mul(priv)
        let msgHex = "123456789a"
        let data = cryptoJS.enc.Hex.parse(msgHex)
        let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
        console.log('cypher: ', cryptoJS.enc.Hex.stringify(cypher))
        let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
        let plainHex = cryptoJS.enc.Hex.stringify(plain)
        console.log("plainHex: ", plainHex)
        assert.equal(msgHex, plainHex)
```

## Encryption with authorization
- Encrypt a string
```javascript
      let msg = 'hello, string'
      let localAuthPriv = await Rand.randomBN(32)
      let remoteAuthPriv = await Rand.randomBN(32)
      let localAuthPub = P256.g.mul(localAuthPriv)
      let remoteAuthPub = P256.g.mul(remoteAuthPriv)
      let cypherData = await AuthEnc.encryptString(localAuthPriv, remoteAuthPub, msg)
      console.log("cypherData:", cypherData)
      let [verifySig, plain] = AuthEnc.decryptString(remoteAuthPriv, localAuthPub, cypherData)
      if(verifySig){
          console.log("plainData:", plain)
      }
      assert(verifySig)
```

- Encrypt bytes
```javascript
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        let localAuthPriv = await Rand.randomBN(32)
        let remoteAuthPriv = await Rand.randomBN(32)
        let localAuthPub = P256.g.mul(localAuthPriv)
        let remoteAuthPub = P256.g.mul(remoteAuthPriv)
        let cypherData = await AuthEnc.encryptBytes(localAuthPriv, remoteAuthPub, data)
        console.log("cypherData:", cypherData)
        let [verifySig, plain] = AuthEnc.decryptBytes(remoteAuthPriv, localAuthPub, cypherData)
        if(verifySig){
            console.log("plainData:", Hex.fromBytes(plain))
        }
        assert(verifySig)
```

- Encrypt CryptoJSBytes
```javascript
        let msg = 'hello, WordArray(CryptoJSBytes)'
        let msgWordArray = cryptoJS.enc.Utf8.parse(msg)
        let localAuthPriv = await Rand.randomBN(32)
        let remoteAuthPriv = await Rand.randomBN(32)
        let localAuthPub = P256.g.mul(localAuthPriv)
        let remoteAuthPub = P256.g.mul(remoteAuthPriv)
        let cypherData = await AuthEnc.encryptCryptoJSBytes(localAuthPriv, remoteAuthPub, msgWordArray)
        console.log("cypherData:", cypherData)
        let [verifySig, plain] = AuthEnc.decryptCryptoJSBytes(remoteAuthPriv, localAuthPub, cypherData)
        if(verifySig){
            console.log("plainData:", Hex.fromCryptoJSBytes(plain))
        }
        assert(verifySig)
```

## Authorization
```javascript
        import {ECIES, AuthEnc, Authorize} from "@safeheron/crypto-ecies"

        let msg = 'hello'
        msg = cryptoJS.enc.Utf8.parse(msg)
        
        // local author key pair
        let authPriv = await Rand.randomBN(32)
        let authPub = P256.g.mul(authPriv)
        
        let signature = await Authorize.sign(authPriv, msg)
        console.log('sig:', signature)
        console.log('\n\n')
        let verifySig = Authorize.verify(authPub, msg, signature)
        assert(verifySig)
```
