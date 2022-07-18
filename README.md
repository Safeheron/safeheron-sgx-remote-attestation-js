# JS-MPC
## 1. Abstract

### 1.1 Plan

![mpc_plan.png](./img/mpc_plan.png)


### 1.2 Modules


### 1.3 Dependencies

- Big Number: indutny/bn.js
- Elliptic Curve: indutny/elliptic
- Hash: indutny/hash.js

## 2 Number theory
 
- Miller-Rabin primality test

```javascript
const assert = require('assert')
const prime = require('../lib/nty/prime')
let a = new bn('18', 10)
let b = new bn('77777', 10)
//the 12th mersenne prime 2^127-1
let c = new bn('170141183460469231731687303715884105727', 10)
assert(!prime.isprobablyprime(a))
assert(!prime.isprobablyprime(b))
assert(prime.isprobablyprime(c))
```

## 3 Random Number

- Random number generator
```javascript
const rand = require('../lib/rand')
let r = rand.randomBytes(i)
console.log(r.length)
console.log(r)

r = rand.randomBN(i)
console.log(r.toString())
```

- Random prime generator

```javascript
const rand = require('../lib/nty/prime')
let r = rand.getRandomPrime(256/8)
console.log(r.toString())

r = rand.getRandomPrime256Bit()
console.log(r.toString())
```

- Random prime generator with specified byteLen, which means the highest bit is 1

```javascript
const rand = require('../lib/nty/prime')
let r = rand.getRandomPrimeStrict(256/8)
console.log(r.toString())

r = rand.getRandomPrimeStrict256Bit()
console.log(r.toString())
```

- Special random number generator

```javascript
let max = new BN('88888888', 16)
let r = await rand.randomBNLt(max)
assert(r.lt(max), "lt")
r = await rand.randomBNLtGCD(max)
assert(r.lt(max), "lt")
assert(r.gcd(max).eqn(1), "gcd test failed")
```


## 4 Hash Commitment

```javascript
const BN = require('bn.js')
const assert = require('assert')
const HashCommitment = require('..').commitment

var msg = new BN('61630392401948106105179362333906431572040870001829469719032882728467924668429', 10)
var blind = new BN('97324513931665327983910040089283784409389314232230480988378402393871690930585', 10)
var com = new HashCommitment.createComWithBlind(msg, blind)
var expectedCom = new BN('16875086368045186523530779402610682073770440290332351815832659472313617226983', 10)
assert.strictEqual(com.eq(expectedCom), true)
```

## 5 Pailliar CryptoSystem 

- Encrypt and decrypt

Mark: Function "encryptWithR" but not "encrypt" is advised.

```javascript
const keyPair = await paillier.createKeyPair(512/8)
const priv = keyPair[0]
const pub = keyPair[1]
let m = await rand.randomBNLt(pub.n)
let r = await rand.randomBNLtGCD(pub.n)
let c1 = pub.encryptWithR(m, r)
let c2 = await pub.encrypt(m)
let m1 = priv.decrypt(c1)
let m2 = priv.decrypt(c2)
console.log("m:", m.toString())
console.log("pub.n:", pub.n.toString())
console.log("m1:", m1.toString())
console.log("m2:", m2.toString())
assert(m.eq(m1) && m.eq(m2), "should equal")
```

- Homomorphic Add
```javascript
const keyPair = await paillier.createKeyPair(512/8)
const priv = keyPair[0]
const pub = keyPair[1]
let m1 = await rand.randomBNLt(pub.n)
let m2 = await rand.randomBNLt(pub.n)
let r1 = await rand.randomBNLtGCD(pub.n)
let r2 = await rand.randomBNLtGCD(pub.n)
let c1 = pub.encryptWithR(m1, r1)
let c2 = pub.encryptWithR(m2, r2)
let eSum = pub.add(c1, c2)
let sum = priv.decrypt(eSum)
sum = sum.mod(pub.n)
console.log("pub.n:", pub.n.toString())
console.log("m1:", m1.toString())
console.log("m2:", m2.toString())
console.log("sum:", sum.toString())
let expected = m1.add(m2).mod(pub.n)
assert(sum.eq(expected), "should equal")
```

- Homomorphic Add Plain Big Number
```javascript
const keyPair = await paillier.createKeyPair(512/8)
const priv = keyPair[0]
const pub = keyPair[1]
let m = await rand.randomBNLt(pub.n)
let b = await rand.randomBNLt(pub.n)
let r = await rand.randomBNLtGCD(pub.n)
let c = pub.encryptWithR(m, r)
let eSum = pub.addPlain(c, b)
let sum = priv.decrypt(eSum)
console.log("pub.n:", pub.n.toString())
console.log("m:", m.toString())
console.log("b:", b.toString())
console.log("sum:", sum.toString())
let expected = m.add(b).mod(pub.n)
assert(sum.eq(expected), "should equal")
```

- Homomorphic Multiply
```javascript
const keyPair = await paillier.createKeyPair(512/8)
const priv = keyPair[0]
const pub = keyPair[1]
let m = await rand.randomBNLt(pub.n)
let k = await rand.randomBNLt(pub.n)
let r = await rand.randomBNLtGCD(pub.n)
let c = pub.encryptWithR(m, r)
let eMK = pub.mul(c, k)
let mk = priv.decrypt(eMK)
console.log("pub.n:", pub.n.toString())
console.log("m:", m.toString())
console.log("k:", k.toString())
console.log("m*k", mk.toString())
assert(mk.eq(m.mul(k).mod(pub.n)), "should equal")
```

## 6 Feldman's Verifiable Secret Sharing Scheme

- Without commitments
```javascript
let threshold = 3
let n = 4
let secret = await rand.randomBNLt(VsssSecp256k1.MaxBN)
let shareIndexs = [
    new BN('1', 10),
    new BN('2', 10),
    new BN('3', 10),
    new BN('4', 10),
]
let shares = await VsssSecp256k1.makeShares(secret, threshold, shareIndexs, n)
let recoveredSecret = VsssSecp256k1.recoverSecret(threshold, [shares[1], shares[2], shares[3]])
assert(secret.eq(recoveredSecret), "should equal")
```

- With commitments
```javascript
let threshold = 3
let n = 4
let secret = await rand.randomBNLt(VsssSecp256k1.MaxBN)
let shareIndexs = [
    await rand.randomBNLt(VsssSecp256k1.MaxBN),
    await rand.randomBNLt(VsssSecp256k1.MaxBN),
    await rand.randomBNLt(VsssSecp256k1.MaxBN),
    await rand.randomBNLt(VsssSecp256k1.MaxBN),
]
let res = await VsssSecp256k1.makeSharesWithCommits(secret, threshold, shareIndexs, n)
let shares = res[0]
let commits = res[1]
for( let i = 0; i < shares.length; i ++){
    VsssSecp256k1.verifyShare(commits, shares[i][0], shares[i][1])
    console.log('- share', i, ': shareIndex=', shares[i][0].toString(), ", share=", shares[i][1].toString())
}
let r = VsssSecp256k1.recoverSecret(threshold, [shares[1], shares[2], shares[3]])
console.log('secret = ', secret.toString())
console.log('recovered = ', r.toString())
assert(secret.eq(r), "should equal")
```

## 7 ECC Encryption
Refer to [./test/ec-enc-test.js](./test/ec-enc-test.js)


## 8 Auth-Key Encryption and Signature
Refer to [./test/auth-key-test.js](./test/auth-key-test.js)

## 9 MPC ECDSA( Support HD Key )

- MPC CoVault Generation
Refer to [./test/hd-ecdsa-vaultgen-test.js](./test/hd-ecdsa-vaultgen-test.js)


- MPC Sign Key Generation
Refer to [./test/hd-ecdsa-signkeygen-test.js](./test/hd-ecdsa-signkeygen-test.js)

## 10 Key Export

- Export Co-Vault key share(For Co-Signer):

```javascript
        let base64CypherKeyShare = await KeyExport.exportCypherCoVaultKeyShare(base64CoVaultKey, remoteAuthPub)
        let [verifySig, base64KeyShare] = await KeyExport.verifyCypherCoVaultKeyShare(base64CypherKeyShare, base64CoSignKey[2])
        assert(verifySig)
        let [share, chainCode] = await KeyExport.getShareAndChainCode(base64KeyShare)
```

- Export Co-Vault key share(For Owner himself):
```javascript
        let base64PlainKeyShare = await KeyExport.exportPlainCoVaultKeyShare(base64CoVaultKey)
        let verifySig = await KeyExport.verifyPlainCoVaultKeyShare(base64PlainKeyShare, base64CoSignKey)
        assert(verifySig)
        let [share, chainCode] = await KeyExport.getShareAndChainCode(base64PlainKeyShare)
```

## 引用

- [Paper: Fast Multiparty Threshold ECDSA with Fast Trustless Setup](https://eprint.iacr.org/2019/114.pdf)
- [Elliptic curve](https://en.wikipedia.org/wiki/Elliptic_curve)
- [Elliptic Curve Digital Signature Algorithm
](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
- [Jacobian Coordinates](https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates)
- [Paillier's Cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [Carmichael function](https://en.wikipedia.org/wiki/Carmichael_function)
- [wiki:Feldman's Verifiable_secret_sharing](https://en.wikipedia.org/wiki/Verifiable_secret_sharing)
- [Commitment scheme](https://en.wikipedia.org/wiki/Commitment_scheme)
- [Schnorr Non-interactive Zero-Knowledge Proof](https://tools.ietf.org/html/rfc8235)
- [Primality Test](https://en.wikipedia.org/wiki/Primality_test)
- [Euler](https://en.wikipedia.org/wiki/Euler%27s_totient_function)
- [Miller-Rabin Primality Test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
- [Technical Guideline TR-02102-2
Cryptographic Mechanisms:
Recommendations and Key Lengths](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile)
- [ZK proof using homomorphic ElGamal encryption](https://www.win.tue.nl/~berry/papers/ST04asiacrypt.pdf)
