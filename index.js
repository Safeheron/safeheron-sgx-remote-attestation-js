'use strict';
const assert = require('assert');
const BN = require('bn.js');
const {ECIES} = require('@safeheron/crypto-ecies');
const elliptic = require('elliptic');
const EC = require('elliptic').ec;
const P256 = new EC('p256');
const crypto_hash = require('crypto');
const {UrlBase64} = require("@safeheron/crypto-utils");
const cryptoJS = require("crypto-js");
const {Certificate} = require('@fidm/x509');
const fs = require('fs');

// read data from data.json
const json_data_1 = require('./data.json');

// hash the message
function sha256Digest(message, encoding) {
    return crypto_hash.createHash('sha256')
        .update(message)
        .digest(encoding);
}

// get the key meta hash
function getKeyMetaHash(json_key_info, key) {
    let hash = "";
    for (const [keyTemp, value] of Object.entries(json_key_info[key])) {
        hash = hash + value;
    }
    let temp = hash.replace(/,/g, "");
    return sha256Digest(Buffer.from(temp), 'hex');
}

function genPubKey() {
    let private_key_list = json_data_1["private_key_list"];
    let public_key_list = {};

    // generate the public key according to the private key in "private_key_list"
    private_key_list.forEach(key => {
        const pri = new BN(key, 16)
        const pub = P256.g.mul(pri)
        public_key_list["04" + pub.getX().toString(16) + pub.getY().toString(16)] = pri.toString(16)
    })
    return public_key_list;
}

// get the public key list hash
function sha256DigestArray(messages) {
    let sha256 = cryptoJS.algo.SHA256.create({asBytes: true});
    for (let m in messages) {
        sha256.update(messages[m])
    }
    let digest = sha256.finalize();
    return digest.toString(cryptoJS.enc.Hex);
};

function getAppReportHash(key_shard_pkg, json_pubkey_list_hash) {
    let hashList = [];
    let keyShard;
    let key_meta_hash;
    let pubkey_list = genPubKey();

    // collect the public key
    for (let pkg_element in key_shard_pkg) {
        keyShard = key_shard_pkg[pkg_element];
        hashList.push(keyShard['public_key']);
    }

    // 1. decrypt the value of 'encrypt_key_info' using the corresponding private key
    // 2. parse the plain to a JSON object
    let encrypt_key_info = Buffer.from(keyShard['encrypt_key_info'].toString(), 'hex');
    let pri_key = new BN(pubkey_list[keyShard['public_key']], 16);
    let plain_buffer = Buffer.from(ECIES.decryptBytes(pri_key, encrypt_key_info));
    const key_info = JSON.parse(plain_buffer.toString());

    // get key meta hash
    key_meta_hash = getKeyMetaHash(key_info, 'key_meta');

    // verify the public key list hash
    let pubkey_list_hash = sha256DigestArray(hashList);
    // assert.strictEqual(pubkey_list_hash, json_pubkey_list_hash);
    console.log("*************************************************************************************************************");
    console.log("The public key list hash from data.json: " + pubkey_list_hash);
    console.log("The calculated public key list hash: " + json_pubkey_list_hash);
    console.log("*************************************************************************************************************");

    if (pubkey_list_hash != json_pubkey_list_hash){
        console.log("Verify the public key list hash failed!\n");
        return false;
    }
    console.log("1. The public key list hash has been verified successfully!\n");

    // hash the concatenation of public key list hash and key meta hash
    return sha256Digest(Buffer.concat([Buffer.from(pubkey_list_hash, 'hex'), Buffer.from(key_meta_hash, 'hex')]), 'hex');
}

function getQeReportHash(tee_report_buffer) {
    // the size and offset attestation public key
    let attest_public_key_offset = 0x1f4;
    let attest_public_key_size = 0x40;

    // the offset of authentication data structure
    let auth_data_struct_offset = 0x3f4;

    // the size and offset of authentication data
    let auth_data_len = tee_report_buffer.readUInt16LE(auth_data_struct_offset);
    let auth_data_offset = auth_data_struct_offset + 2;

    // get the attestation public key and authentication data
    let attest_public_key = tee_report_buffer.slice(attest_public_key_offset, attest_public_key_offset + attest_public_key_size);
    let auth_data = tee_report_buffer.slice(auth_data_offset, auth_data_offset + auth_data_len);

    // hash the concatenation of the attestation public key and authentication data
    return sha256Digest(Buffer.concat([attest_public_key, auth_data]), 'hex');
}

function verifyCertChain(tee_report_buffer) {
    // the offset of authentication data structure
    let auth_data_struct_offset = 0x3f4;

    // the size of authentication data
    let auth_data_size = tee_report_buffer.readUInt16LE(auth_data_struct_offset);

    // the offset of Certification Data
    let cert_chain_offset = 0x3f4 + 2 + auth_data_size + 2 + 4;
    // get certification chain
    let certification_data = tee_report_buffer.slice(cert_chain_offset);

    // get certification from certification chain
    let keyCert = [];
    const cert_length = 25;
    let k = 0;
    let u = 0;
    let tmp;
    for (let t = 0; t < 3; t++) {
        tmp = certification_data.indexOf("-----END CERTIFICATE-----", k)
        keyCert[t] = certification_data.slice(u, tmp + cert_length);
        k = tmp + cert_length;
        u = tmp + cert_length;
    }

    const pck_cert =  Certificate.fromPEM(keyCert[0]);
    const processor_cert = Certificate.fromPEM(keyCert[1]);
    const sgx_root =  Certificate.fromPEM(keyCert[2]);

    // verify certification chain
    let result = processor_cert.checkSignature(pck_cert) == null &&
                sgx_root.checkSignature(processor_cert) == null &&
                sgx_root.checkSignature(sgx_root) == null &&
                pck_cert.isIssuer(processor_cert) == true &&
                processor_cert.isIssuer(sgx_root) == true &&
                sgx_root.isIssuer(sgx_root) == true;

    return [result, pck_cert];
}

// verify app report signature
function verifyAppReportSig(tee_report_buffer) {
    // the size and the offset of signature and attestation public key
    let app_signature_offset = 0x1b4;
    let app_signature_size = 0x40;
    let attest_public_key_offset = 0x1f4;
    let attest_public_key_size = 0x40;

    let ecdsa = new elliptic.ec('p256');

    // hash report header and app report
    // convert it to BN
    let header_and_report = tee_report_buffer.slice(0, 432);
    let hash = new BN(sha256Digest(header_and_report, 'hex'), 16);

    // get ISV enclave report signature
    let signature = tee_report_buffer.slice(app_signature_offset, app_signature_offset + app_signature_size);
    let sig = {
        r: signature.slice(0, 32).toString('hex'),
        s: signature.slice(32, 64).toString('hex'),
    };

    // convert attestation public key to a point on curve P256
    let attest_public_key = tee_report_buffer.slice(attest_public_key_offset, attest_public_key_offset + attest_public_key_size);
    let x = new BN(attest_public_key.slice(0, 32).toString('hex'), 16);
    let y = new BN(attest_public_key.slice(32, 64).toString('hex'), 16);
    let pub = P256.curve.point(x, y);

    // return the verification result
    return ecdsa.verify(hash, sig, pub);
}

// verify qe report signature
function verifyQeReportSig(tee_report_buffer, pck_cert) {
    // the size and the offset of the signature and attestation public key
    let qe_report_offset = 0x234;
    let qe_report_size = 0x180;
    let qe_signature_offset = 0x3b4;
    let qe_signature_size = 0x40;

    let ecdsa = new elliptic.ec('p256');

    // hash QE report
    // convert it to BN
    let hash = new BN(sha256Digest(tee_report_buffer.slice(qe_report_offset , qe_report_offset + qe_report_size), 'hex'), 16);

    // get QE report signature
    let signature = tee_report_buffer.slice(qe_signature_offset, qe_signature_offset + qe_signature_size);
    let sig = {
        r: signature.slice(0, 32).toString('hex'),
        s: signature.slice(32, 64).toString('hex'),
    };

    // get the public key from pckCert and convert it to a point on the elliptic curve
    let pub = ecdsa.keyFromPublic(pck_cert.publicKey.keyRaw.toString('hex'), 'hex');

    // return the verification result
    return ecdsa.verify(hash, sig, pub);
};

function verifyReport(tee_report_buffer, app_user_data){

    const [cert_chain_result, pck_cert] = verifyCertChain(tee_report_buffer);
    if (cert_chain_result !== true) {
        console.log("Verify cert chain failed!\n");
        return false;
    }
    console.log("2. The cert chain has been verified successfully!\n");

    // verify App report signature
    const verify_app_result = verifyAppReportSig(tee_report_buffer);
    if (verify_app_result !== true) {
        console.log("Verify App report signature failed!\n");
        return false;
    }
    console.log("3. The App report signature has been verified successfully!\n");

    // verify QE report signature
    const verify_qe_result = verifyQeReportSig(tee_report_buffer, pck_cert);
    if (verify_qe_result !== true) {
        console.log("Verify QE report signature failed!\n");
        return false;
    }
    console.log("4. The QE report signature has been verified successfully!\n");

    const qe_report_hash = getQeReportHash(tee_report_buffer);

    // define the offset and size of App Report Data and QE Report Data
    let app_report_data_offset = 0x170;
    let app_report_data_size = 0x20;
    let qe_report_data_offset = 0x374;
    let qe_report_data_size = 0x20;

    // get Report Data from report
    let app_report_data = tee_report_buffer.slice(app_report_data_offset, app_report_data_offset + app_report_data_size).toString('hex');
    let qe_report_data = tee_report_buffer.slice(qe_report_data_offset, qe_report_data_offset + qe_report_data_size).toString('hex');

    // the data needed to be verified
    console.log("*************************************************************************************************************");
    console.log("The calculated user data: " + app_user_data);
    console.log("The user data from tee_report: " + app_report_data);
    console.log("*************************************************************************************************************");
    console.log("The calculated QE report data: " + qe_report_hash);
    console.log("The QE report data from tee_report: " + qe_report_data);
    console.log("*************************************************************************************************************");

    // verify user data
    if (app_user_data !== app_report_data) {
        console.log("Verify App report data failed!\n");
        return false;
    }
    console.log("5. User Data has been verified successfully!\n");

    if (qe_report_hash !== qe_report_data) {
        console.log("Verify QE report data failed!\n");
        return false;
    }
    console.log("6. QE Report Data has been verified successfully!\n");

    return true;
}

function main(){
    let json_data = json_data_1["tee_return_data"];
    const tee_report = json_data['tee_report'];
    let tee_report_bytes = UrlBase64.toBytes(tee_report);
    let tee_report_buffer = Buffer.from(tee_report_bytes);

    const key_shard_pkg = json_data['key_shard_pkg'];
    const json_pubkey_list_hash = json_data['pubkey_list_hash'];

    // get User Data
    const app_user_data = getAppReportHash(key_shard_pkg, json_pubkey_list_hash);
    if (app_user_data == false){
        console.log("Verify TEE Report failed!\n");
        return
    }
    // verify TEE Report
    const result = verifyReport(tee_report_buffer, app_user_data);
    if (result) {
        console.log("Verify TEE Report successfully!\n");
    }
    else {
        console.log("Verify TEE Report failed!\n");
    }
}

main()

