"""Explicit network-guarded CIDRegistry writes for local 31337 or Sepolia."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from web3 import HTTPProvider, Web3

from .cid_registry import DEFAULT_RPC_URL, LOCAL_CHAIN_ID

SEPOLIA_CHAIN_ID = 11155111
SEPOLIA_DEPLOYMENT = Path(__file__).with_name("deployments") / "sepolia.json"
ABI_PATH = Path(__file__).with_name("cid_registry_abi.json")
HARDHAT_DEV_ADDRESSES = {
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
    "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65", "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
    "0x976ea74026e726554db657fa54763abd0c3a0aa9", "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
    "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f", "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
    "0xbcd4042de499d14e55001ccbb24a551f3b954096", "0x71be63f3384f5fb98995898a86b02fb2426c5788",
    "0xfabb0ac9d68b0b445fb7357272ff202c5651694a", "0x1cbd3b2770909d4e10f157cabc84c7264073c9ec",
    "0xdF3e18d64BC6A983f673Ab319CCaE4f1a57C7097".lower(), "0xcd3b766ccdd6ae721141f452c550ca635964ce71",
    "0x2546bcfc1213d7a70222df1864d956f4545d5d6f", "0xbda5747bfd65f08deb54cb465eb87d40e51b197e",
    "0xdd2fd4581271e230360230f9337d5c0430bf44c0", "0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199",
}


def record_id_for_file(file_id: str) -> bytes:
    """Hash a random UUID; no filename, user ID, or plaintext reaches the chain."""
    import uuid
    parsed = uuid.UUID(file_id)
    return hashlib.sha256(b"adaptive-security-file-record-v1:" + parsed.bytes).digest()


def _config(environ: dict[str, str] | None = None, *, require_signer: bool = True) -> tuple[str, int, str, str | None, Path, str]:
    env = environ if environ is not None else os.environ
    network = env.get("ETHEREUM_NETWORK", "").lower()
    if network not in {"local", "sepolia"}:
        raise RuntimeError("Blockchain registration is disabled; configure local or sepolia explicitly")
    expected_chain = LOCAL_CHAIN_ID if network == "local" else SEPOLIA_CHAIN_ID
    try:
        chain_id = int(env.get("ETHEREUM_CHAIN_ID", str(expected_chain)))
    except ValueError as exc:
        raise RuntimeError("Configured blockchain chain ID is invalid") from exc
    if chain_id != expected_chain:
        raise RuntimeError("Configured blockchain chain ID does not match selected network")
    rpc = env.get("SEPOLIA_RPC_URL") if network == "sepolia" else env.get("CID_REGISTRY_RPC_URL", DEFAULT_RPC_URL)
    if not rpc:
        raise RuntimeError("Sepolia RPC endpoint is not configured")
    parsed = urlparse(rpc)
    if network == "sepolia" and parsed.scheme != "https":
        raise RuntimeError("Sepolia requires an HTTPS RPC endpoint")
    if network == "local" and (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
        raise RuntimeError("Local blockchain mode only permits a loopback HTTP endpoint")
    address = env.get("CID_REGISTRY_ADDRESS", "")
    deployment_path = SEPOLIA_DEPLOYMENT if network == "sepolia" else Path(env.get("CID_REGISTRY_DEPLOYMENT", Path(__file__).with_name("deployments") / "localhost.json"))
    if not address and deployment_path.exists():
        address = json.loads(deployment_path.read_text()).get("address", "")
    if not Web3.is_address(address):
        raise RuntimeError("CIDRegistry address is not configured")
    private_key = env.get("SEPOLIA_DEPLOYER_PRIVATE_KEY") if network == "sepolia" else None
    if network == "sepolia" and require_signer and not private_key:
        raise RuntimeError("Sepolia deployer key is not configured")
    return network, chain_id, rpc, private_key, deployment_path, Web3.to_checksum_address(address)


def register_local_or_sepolia_cid(file_id: str, cid: str, *, environ: dict[str, str] | None = None) -> dict:
    network, chain_id, rpc, private_key, _deployment_path, address = _config(environ)
    account = None
    if private_key:
        account = Web3().eth.account.from_key(private_key)
        if account.address.lower() in HARDHAT_DEV_ADDRESSES:
            raise RuntimeError("A default Hardhat development key cannot be used on Sepolia")
    w3 = Web3(HTTPProvider(rpc, request_kwargs={"timeout": 15}))
    if not w3.is_connected() or w3.eth.chain_id != chain_id:
        raise RuntimeError("Configured RPC did not connect to the expected chain")
    if not cid or len(cid) > 256:
        raise ValueError("CID is invalid")
    abi = json.loads(ABI_PATH.read_text())
    if not w3.eth.get_code(address):
        raise RuntimeError("No contract is deployed at the configured CIDRegistry address")
    contract = w3.eth.contract(address=address, abi=abi)
    record_id = record_id_for_file(file_id)
    existing, timestamp, _submitter = contract.functions.getCID(record_id).call()
    if existing:
        if existing != cid:
            raise RuntimeError("CID record is already registered with a different CID")
        return {"status": "already_registered", "chain_id": chain_id, "record_id": Web3.to_hex(record_id), "cid": existing, "transaction_hash": None}
    if not private_key:
        accounts = w3.eth.accounts
        if not accounts:
            raise RuntimeError("Local node did not provide an unlocked development account")
        sender = accounts[0]
    owner = contract.functions.owner().call()
    sender = account.address if private_key else sender
    if owner.lower() != sender.lower():
        raise RuntimeError("Configured transaction account is not the CIDRegistry owner")
    function = contract.functions.storeCID(record_id, cid)
    if private_key:
        tx = function.build_transaction({"from": sender, "nonce": w3.eth.get_transaction_count(sender), "chainId": chain_id, "gas": 200_000, "gasPrice": w3.eth.gas_price})
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    else:
        tx_hash = function.transact({"from": sender})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1:
        raise RuntimeError("CIDRegistry write transaction failed")
    actual, stored_timestamp, _ = contract.functions.getCID(record_id).call()
    if actual != cid or stored_timestamp <= 0:
        raise RuntimeError("CIDRegistry read-back validation failed")
    return {"status": "registered", "chain_id": chain_id, "record_id": Web3.to_hex(record_id), "cid": actual, "transaction_hash": Web3.to_hex(tx_hash)}


def verify_registered_cid(file_id: str, expected_cid: str, *, environ: dict[str, str] | None = None) -> dict:
    _network, chain_id, rpc, _private_key, _deployment_path, address = _config(environ, require_signer=False)
    w3 = Web3(HTTPProvider(rpc, request_kwargs={"timeout": 15}))
    if not w3.is_connected() or w3.eth.chain_id != chain_id:
        raise RuntimeError("Configured RPC did not connect to the expected chain")
    abi = json.loads(ABI_PATH.read_text())
    if not w3.eth.get_code(address):
        raise RuntimeError("No contract is deployed at the configured CIDRegistry address")
    contract = w3.eth.contract(address=address, abi=abi)
    record_id = record_id_for_file(file_id)
    actual, timestamp, _submitter = contract.functions.getCID(record_id).call()
    return {"valid": bool(actual and actual == expected_cid and timestamp > 0), "chain_id": chain_id,
            "record_id": Web3.to_hex(record_id), "cid": actual, "timestamp": int(timestamp), "contract_address": address}
