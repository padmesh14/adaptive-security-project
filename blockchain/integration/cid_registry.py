"""Submit and read CIDRegistry records on a local Hardhat JSON-RPC node."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlparse

from web3 import HTTPProvider, Web3


BLOCKCHAIN_DIR = Path(__file__).resolve().parents[1]
ARTIFACT_PATH = BLOCKCHAIN_DIR / "artifacts/contracts/CIDRegistry.sol/CIDRegistry.json"
DEPLOYMENT_PATH = BLOCKCHAIN_DIR / "integration/deployments/localhost.json"
DEFAULT_RPC_URL = "http://127.0.0.1:8545"
LOCAL_CHAIN_ID = 31337


def derive_record_id(namespace: str, logical_identifier: str, secret: str) -> bytes:
    """Return a deterministic bytes32 HMAC without putting the label on-chain."""
    if not namespace or not logical_identifier or not secret:
        raise ValueError("namespace, logical_identifier, and secret must be non-empty")
    message = f"adaptive-multi-layer-security:{namespace}:{logical_identifier}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).digest()


def connect_local(rpc_url: str | None = None) -> Web3:
    """Connect only to loopback and verify the Hardhat development chain ID."""
    endpoint = rpc_url or os.getenv("CID_REGISTRY_RPC_URL", DEFAULT_RPC_URL)
    parsed = urlparse(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("CIDRegistry integration is restricted to a local HTTP JSON-RPC endpoint")
    web3 = Web3(HTTPProvider(endpoint, request_kwargs={"timeout": 10}))
    if not web3.is_connected():
        raise ConnectionError(f"Cannot connect to local Hardhat JSON-RPC at {endpoint}")
    if web3.eth.chain_id != LOCAL_CHAIN_ID:
        raise RuntimeError(f"Expected local Hardhat chain ID {LOCAL_CHAIN_ID}")
    return web3


def _artifact() -> dict:
    with ARTIFACT_PATH.open(encoding="utf-8") as artifact_file:
        return json.load(artifact_file)


def deploy_local_registry(web3: Web3, deployment_path: Path = DEPLOYMENT_PATH) -> str:
    """Deploy CIDRegistry using the first unlocked account on the local node."""
    artifact = _artifact()
    accounts = web3.eth.accounts
    if not accounts:
        raise RuntimeError("The local node did not provide an unlocked development account")
    factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx_hash = factory.constructor().transact({"from": accounts[0]})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1 or receipt.contractAddress is None:
        raise RuntimeError("CIDRegistry deployment failed")
    deployment_path.parent.mkdir(parents=True, exist_ok=True)
    deployment_path.write_text(
        json.dumps(
            {
                "address": receipt.contractAddress,
                "chain_id": web3.eth.chain_id,
                "contract": "CIDRegistry",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return receipt.contractAddress


def load_registry(web3: Web3, deployment_path: Path = DEPLOYMENT_PATH):
    with deployment_path.open(encoding="utf-8") as deployment_file:
        deployment = json.load(deployment_file)
    if deployment.get("chain_id") != LOCAL_CHAIN_ID:
        raise RuntimeError("Deployment metadata is not for the local Hardhat chain")
    artifact = _artifact()
    return web3.eth.contract(address=Web3.to_checksum_address(deployment["address"]), abi=artifact["abi"])


def store_and_read_cid(
    registry,
    web3: Web3,
    record_id: bytes,
    cid: str,
) -> tuple[str, int, str, str]:
    """Submit a CID and return CID, timestamp, submitter, and transaction hash."""
    if len(record_id) != 32:
        raise ValueError("record_id must be exactly 32 bytes")
    if not cid:
        raise ValueError("cid must be non-empty")
    accounts = web3.eth.accounts
    if not accounts:
        raise RuntimeError("The local node did not provide an unlocked development account")
    tx_hash = registry.functions.storeCID(record_id, cid).transact({"from": accounts[0]})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError("CIDRegistry storeCID transaction reverted")
    stored_cid, timestamp, submitter = registry.functions.getCID(record_id).call()
    return stored_cid, timestamp, submitter, tx_hash.hex()
