/// <reference types="node" />
import { VerifyData } from "./interface";
import { Buffer } from "buffer";
export declare class RemoteAttestor {
    private logInfo;
    constructor();
    verifyReport(report: string | VerifyData, sgx_root_cert: string | Buffer): boolean;
    exportLog(): string;
    private appendLog;
    private sha256Digest;
    private getKeyMetaHash;
    private genPubKey;
    private sha256DigestArray;
    private getAppReportHash;
    private getQeReportHash;
    private verifyCertChain;
    private verifyAppReportSig;
    private verifyQeReportSig;
    private verifyReportStepByStep;
}
