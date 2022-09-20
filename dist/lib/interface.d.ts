export interface VerifyData {
    tee_return_data: {
        pubkey_list_hash: string;
        key_shard_pkg: KeyShardPKGItem[];
        tee_report: string;
    };
    private_key: string;
}
interface KeyShardPKGItem {
    public_key: string;
    encrypt_key_info: string;
}
export {};
