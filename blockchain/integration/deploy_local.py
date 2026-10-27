"""Deploy CIDRegistry to the running local Hardhat node."""

from .cid_registry import connect_local, deploy_local_registry


def main() -> None:
    address = deploy_local_registry(connect_local())
    print(f"CIDRegistry deployed to local Hardhat network at {address}")


if __name__ == "__main__":
    main()
