'use strict'
const assert = require('assert')
const BN = require('bn.js');
const {ECIES} = require('@safeheron/crypto-ecies');
const elliptic = require('elliptic')
const EC = require('elliptic').ec;
const P256 = new EC('p256')
const crypto = require('crypto')
const {UrlBase64} = require("@safeheron/crypto-utils")
const cryptoJS = require("crypto-js");
const {Certificate} = require('@fidm/x509')
const fs = require('fs');

const sgxQuoteHeaderOffset = 0

// Hash the message
function sha256Digest(message, encoding) {
    return crypto.createHash('sha256')
        .update(message)
        .digest(encoding)
}

//
function sha256DigestArray(messages) {
    let sha256 = cryptoJS.algo.SHA256.create({asBytes: true});
    for (var m in messages) {
        sha256.update(messages[m])
    }
    let digest = sha256.finalize();
    return digest.toString(cryptoJS.enc.Hex);

}

function genPubKey() {
    const testKeyA = "8bab3e786c5e1ffd30dc475f62f3a5cb1aa0c5efe8ba2019e528c77ac2ba99bc"
    const testKeyB = "a37359cf38aab6208599416a74e5fef293cbc3cb5e03a038e3ef37eb65ad1289"
    const testKeyC = "2207e9e61ac486f2c01cfd926fe3f24252b36a68d40ce6bfdf3c5f2e5b72b7e8"
    let   publicKeyList = {};
    [testKeyA, testKeyB, testKeyC].forEach(key => {
        const priv = new BN(key, 16)
        const pub = P256.g.mul(priv)
        publicKeyList["04" + pub.getX().toString(16) + pub.getY().toString(16)] = priv.toString(16)
    })
    return publicKeyList
}

// Get the data from the report
function getTeeData(bytes) {
    const reportBegin = 0x80
    const reportSize = 0x180
    const hashDataOffset = 0
    const hashDataSize = 0x1b0
    const sgxQuoteHeaderSize = 0x30
    const signatureDataLenOffset = 0x1b0
    const sgxReportBodyAppOffset = 0x30
    const sgxReportBodySize = 0x180
    const sgxQlEcdsaSigDataSize = 0x240
    const sgxQlEcdsaSigDataOffset = 0x1b4
    const authDataLenSize = 2
    const authDataOffset = 2

    let text = Buffer.from(bytes)
    console.log(text.length)
    let hashData = text.slice(hashDataOffset, hashDataSize)  //header + isv-report
    // 0 -47 header
    // 48 - 432 isv-report
    // 436 - 1012 sgxQlEcdsaSigData
    // 1013 - 1014 size


    let signatureDataLen = text.readUInt32LE(signatureDataLenOffset)
    let authCertificationData = text.slice(sgxQlEcdsaSigDataOffset + sgxQlEcdsaSigDataSize, sgxQlEcdsaSigDataOffset + signatureDataLen)//till the end of the report
    let authDataLen = authCertificationData.readUInt16LE(0)
    let sgxQlCertificationData = authCertificationData.slice(authDataLen + authDataLenSize)
    let certificationData = sgxQlCertificationData.slice(6)


    let appReportBody = text.slice(sgxReportBodyAppOffset, sgxQuoteHeaderSize + sgxReportBodySize)

    let sgxQlEcdsaSigData = text.slice(sgxQlEcdsaSigDataOffset, sgxQlEcdsaSigDataOffset + sgxQlEcdsaSigDataSize)
    let qeReportBody = sgxQlEcdsaSigData.slice(reportBegin, reportBegin + reportSize)
    let sgxQlAuthData = authCertificationData.slice(authDataOffset, authDataLen + authDataLenSize)
    console.log("sgxQlAuthData: " + sgxQlAuthData)
    let qeHash = sha256Digest(Buffer.concat([sgxQlEcdsaSigData.slice(64, 128), sgxQlAuthData]), 'hex')
    console.log(Buffer.concat([sgxQlEcdsaSigData.slice(64, 128), sgxQlAuthData]).length)
    return [hashData, certificationData, sgxQlEcdsaSigData, appReportBody, qeReportBody, qeHash]
}

// load data from the Json file
function dataIn() {
    let text = fs.readFileSync(__dirname + "//" + 'long_text_2022-07-06-17-30-17' + '.txt');
    let jsonObject = JSON.parse(text)
    return jsonObject
}

// get the certificate chain
function getCertChain(certificationData) {
    let keyCert = []
    const certLength = 25
    let k = 0
    let u = 0
    let tmp
    for (let t = 0; t < 3; t++) {
        tmp = certificationData.indexOf("-----END CERTIFICATE-----", k)
        keyCert[t] = certificationData.slice(u, tmp + certLength)
        k = tmp + certLength
        u = tmp + certLength
    }

    const pckCert =  Certificate.fromPEM(keyCert[0])
    const processorCert = Certificate.fromPEM(keyCert[1])
    const sgxRoot =  Certificate.fromPEM(keyCert[2])
    return [pckCert, processorCert, sgxRoot]
}

// check the certificate if it is valid
function checkCertChain(pckCert, processorCert, sgxRoot) {
    return (processorCert.checkSignature(pckCert) == null &&
        sgxRoot.checkSignature(processorCert) == null &&
        sgxRoot.checkSignature(sgxRoot) == null &&
        pckCert.isIssuer(processorCert) == true &&
        processorCert.isIssuer(sgxRoot) == true &&
        sgxRoot.isIssuer(sgxRoot) == true)
}

// check the Isv report signature if it is valid
function checkHeaderIsvReportSig(hashHeadIsvReport, sgxQlEcdsaSigData) {
    const sigOffset = 0
    const sigSize = 64
    const attestPubKeyOffset = 64
    const attestPubKeySize = 64
    let ecdsa = new elliptic.ec('p256')
    let hash = new BN(sha256Digest(hashHeadIsvReport, 'hex'), 16)
    let signature = sgxQlEcdsaSigData.slice(sigOffset, sigSize)
    let sig = {
        r: signature.slice(0, 32).toString('hex'),
        s: signature.slice(32, 64).toString('hex'),
    }
    let attestPubKey = sgxQlEcdsaSigData.slice(attestPubKeyOffset, attestPubKeyOffset + attestPubKeySize)
    let x = new BN(attestPubKey.slice(0, 32).toString('hex'), 16)
    let y = new BN(attestPubKey.slice(32, 64).toString('hex'), 16)
    let pub = P256.curve.point(x, y)

    return ecdsa.verify(hash, sig, pub)
}

// check the quote enclave report signature if it is valid
function checkQeReportSig(pckCert, sgxQlEcdsaSigData) {
    const sigOffset = 0x200
    const rSize = 32
    const sSize = 32
    const reportBegin = 0x80
    const reportSize = 0x180
    let ecdsa = new elliptic.ec('p256')
    //  get hash     qe_report
    let hash = new BN(sha256Digest(sgxQlEcdsaSigData.slice(reportBegin , reportBegin + reportSize), 'hex'), 16)

    // Get r,s
    let sig = {
        r: sgxQlEcdsaSigData.slice(sigOffset, sigOffset + rSize).toString('hex'),
        s: sgxQlEcdsaSigData.slice(sigOffset + rSize, sigOffset + rSize+sSize).toString('hex'),
    }
    // verify signature
    let pub = ecdsa.keyFromPublic(pckCert.publicKey.keyRaw.toString('hex'), 'hex');

    return ecdsa.verify(hash, sig, pub)
}

// get the key meta hash
function getKeyMetaHash(obj, key) {
    var hash = "";
    for (const [keyTemp, value] of Object.entries(obj[key])) {
        hash = hash + value;
    }
    let temp = hash.replace(/,/g, "")
    return sha256Digest(Buffer.from(temp), 'hex')
}

let hashList = []
let keyMetaHashCode
let gEnclaveId

let pubKeyHashCalculate

let gQeHash
let gAppHash

let gAppUserData
let gQeUserData
describe('arweave test', async function () {
    it('verity report', async function () {
        let jsonKeyShardsGenerationResult = dataIn()
        let pubKeyList = genPubKey()

        // get public key list hash
        const pubKeyListHash = jsonKeyShardsGenerationResult['pubkey_list_hash']

        // get data from tee report
        const teeReport = jsonKeyShardsGenerationResult['tee_report']
        let teeReportBytes = UrlBase64.toBytes(teeReport);
        const [hashData, certificationData, sgxQlEcdsaSigData, appReportBody, qeReportBody, qeHash] = getTeeData(teeReportBytes)
        gQeHash = qeHash
        gEnclaveId = appReportBody.slice(64, 64 + 32).toString('hex')
        gAppUserData = appReportBody.slice(64 * 5, 64 * 5 + 32).toString('hex')
        gQeUserData = qeReportBody.slice(64 * 5, 64 * 5 + 32).toString('hex')
        const [pckCert, processorCert, sgxRoot] = getCertChain(certificationData)

        assert.strictEqual(checkCertChain(pckCert, processorCert, sgxRoot), true)
        assert.strictEqual(checkHeaderIsvReportSig(hashData, sgxQlEcdsaSigData), true)
        assert.strictEqual(checkQeReportSig(pckCert, sgxQlEcdsaSigData), true)


        let jsonKeyShardPkg = jsonKeyShardsGenerationResult['key_shard_pkg']
        for (let pkgElement in jsonKeyShardPkg) {

            const keyShard = jsonKeyShardPkg[pkgElement]

            hashList.push(keyShard['public_key'])

            let encryptKeyInfo = Buffer.from(keyShard['encrypt_key_info'].toString(), 'hex')
            let newPriv = new BN(pubKeyList[keyShard['public_key']], 16)
            let plain = ECIES.decryptBytes(newPriv, encryptKeyInfo)
            let plainBuf = Buffer.from(plain)
            const keyInfo = JSON.parse(plainBuf.toString())
            keyMetaHashCode = getKeyMetaHash(keyInfo, 'key_meta')
        }

        console.log("enclave ID: " + gEnclaveId)
        pubKeyHashCalculate = sha256DigestArray(hashList)

        console.log("pubKeyHashCalculate: " + pubKeyHashCalculate)
        console.log("pubKeyListHash: " + pubKeyListHash)
        assert.strictEqual(pubKeyHashCalculate, pubKeyListHash)

        gAppHash = sha256Digest(Buffer.concat([Buffer.from(pubKeyHashCalculate, 'hex'), Buffer.from(keyMetaHashCode, 'hex')]), 'hex')

        console.log("app Hash " + gAppHash)
        console.log("enclave userdata: " + gAppUserData)
        console.log("qe Hash " + gQeHash)
        console.log("quote userdata: " + gQeUserData)
        assert.strictEqual(gAppHash, gAppUserData)
        assert.strictEqual(gQeHash, gQeUserData)

    });
})
