import pytest
from blockchain.integration.sepolia_registry import SEPOLIA_CHAIN_ID, _config, record_id_for_file

ADDRESS = "0x" + "12" * 20


def test_local_network_requires_loopback_and_chain_31337():
    env = {"ETHEREUM_NETWORK": "local", "ETHEREUM_CHAIN_ID": "31337", "CID_REGISTRY_RPC_URL": "http://127.0.0.1:8545", "CID_REGISTRY_ADDRESS": ADDRESS}
    assert _config(env)[:3] == ("local", 31337, "http://127.0.0.1:8545")
    with pytest.raises(RuntimeError, match="loopback"):
        _config({**env, "CID_REGISTRY_RPC_URL": "http://rpc.example.org"})
    with pytest.raises(RuntimeError, match="chain ID"):
        _config({**env, "ETHEREUM_CHAIN_ID": "1"})


def test_sepolia_configuration_requires_https_chain_and_key():
    env = {"ETHEREUM_NETWORK": "sepolia", "ETHEREUM_CHAIN_ID": str(SEPOLIA_CHAIN_ID),
           "SEPOLIA_RPC_URL": "https://rpc.example.invalid", "CID_REGISTRY_ADDRESS": ADDRESS,
           "SEPOLIA_DEPLOYER_PRIVATE_KEY": "configured-in-memory-for-test"}
    assert _config(env)[:2] == ("sepolia", SEPOLIA_CHAIN_ID)
    with pytest.raises(RuntimeError, match="HTTPS"):
        _config({**env, "SEPOLIA_RPC_URL": "http://rpc.example.invalid"})
    with pytest.raises(RuntimeError, match="chain ID"):
        _config({**env, "ETHEREUM_CHAIN_ID": "1"})
    with pytest.raises(RuntimeError, match="not configured"):
        _config({key: value for key, value in env.items() if key != "SEPOLIA_DEPLOYER_PRIVATE_KEY"})


def test_random_file_id_maps_to_stable_opaque_bytes32():
    file_id = "1e1d03f0-d47a-452c-b774-87b8dd1b1298"
    derived = record_id_for_file(file_id)
    assert len(derived) == 32
    assert derived == record_id_for_file(file_id)
    assert derived != record_id_for_file("35d9a3af-11cf-4ed3-8cd2-0a8fe0564fc8")
