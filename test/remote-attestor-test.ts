'use strict';
import * as assert from "assert";
import * as BN from "bn.js";
import {RemoteAttestor} from "..";
import * as fs from 'fs';

let sgx_root_cert = fs.readFileSync('./data/Intel_SGX_Provisioning_Certification_RootCA.pem').toString();

let report_data_json = JSON.parse(fs.readFileSync("./data/data.json", "utf8"));

describe('SGX remote attestation:', async function () {
    it('remote attestation', async function () {
        console.time('attestation')
        try {
            let attestor = new RemoteAttestor();
            let success = attestor.verifyReport(report_data_json, sgx_root_cert);
            assert(success);
            console.log(attestor.exportLog());
        }catch (e) {
            console.error(e);
        }
        console.timeEnd('attestation');
    })
})
