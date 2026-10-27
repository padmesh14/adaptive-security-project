"""Submit a local demo CID and read it back from CIDRegistry."""

import argparse
import os

from .cid_registry import connect_local, derive_record_id, load_registry, store_and_read_cid


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True, help="Non-sensitive project namespace")
    parser.add_argument("--record-label", required=True, help="Logical record label; only its HMAC is sent on-chain")
    parser.add_argument("--cid", required=True, help="CID already stored in IPFS/Filebase")
    args = parser.parse_args()
    secret = os.getenv("CID_REGISTRY_RECORD_ID_SECRET")
    if not secret:
        parser.error("Set CID_REGISTRY_RECORD_ID_SECRET in the environment; its value is never printed")

    web3 = connect_local()
    registry = load_registry(web3)
    record_id = derive_record_id(args.namespace, args.record_label, secret)
    cid, timestamp, _submitter, tx_hash = store_and_read_cid(registry, web3, record_id, args.cid)
    print(f"Read-back matches submitted CID: {cid == args.cid}")
    print(f"Stored timestamp is non-zero: {timestamp > 0}")
    print(f"Transaction hash: {tx_hash}")


if __name__ == "__main__":
    main()
