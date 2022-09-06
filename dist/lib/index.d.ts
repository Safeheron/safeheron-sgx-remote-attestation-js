export declare class RemoteAttestor {
    private logInfo;
    private report;
    constructor();
    verifyReport(report: string): boolean;
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
