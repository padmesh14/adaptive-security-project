import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { network } from "hardhat";

const SAMPLE_CID = "QmdpcvPPPSo69QEtJn4eKc6L3H3rVWKWdywUSKABE3SN9y";
const SECOND_CID = "QmXPd7VGyU2qrdEh5JR2d9K57HZxV1AX6ArT31xYUWALCg";

describe("CIDRegistry", () => {
  const connectionPromise = network.create();
  let registry: Awaited<ReturnType<Awaited<typeof connectionPromise>["viem"]["deployContract"]>>;
  let submitter: `0x${string}`;
  let close: () => Promise<void>;

  before(async () => {
    const connection = await connectionPromise;
    close = connection.close;
    const [wallet] = await connection.viem.getWalletClients();
    submitter = wallet.account.address;
    registry = await connection.viem.deployContract("CIDRegistry");
  });

  after(async () => {
    await close?.();
  });

  it("deploys successfully", async () => {
    assert.match(registry.address, /^0x[0-9a-fA-F]{40}$/);
  });

  it("stores and retrieves a CID, timestamp, and submitter", async () => {
    const recordId = `0x${"01".repeat(32)}` as const;
    await registry.write.storeCID([recordId, SAMPLE_CID]);

    const [cid, timestamp, submittedBy] = await registry.read.getCID([recordId]);
    assert.equal(cid, SAMPLE_CID);
    assert.ok(timestamp > 0n);
    assert.equal(submittedBy.toLowerCase(), submitter.toLowerCase());
  });

  it("rejects an empty CID with the contract revert message", async () => {
    const recordId = `0x${"02".repeat(32)}` as const;
    await assert.rejects(
      registry.write.storeCID([recordId, ""]),
      /CID cannot be empty/,
    );
  });

  it("rejects writes from accounts other than the registry owner", async () => {
    const connection = await connectionPromise;
    const [, other] = await connection.viem.getWalletClients();
    const recordId = `0x${"05".repeat(32)}` as const;
    await assert.rejects(
      registry.write.storeCID([recordId, SAMPLE_CID], { account: other.account }),
      /Only registry owner can write/,
    );
  });

  it("does not allow a registered record to be overwritten", async () => {
    const recordId = `0x${"06".repeat(32)}` as const;
    await registry.write.storeCID([recordId, SAMPLE_CID]);
    await assert.rejects(
      registry.write.storeCID([recordId, SECOND_CID]),
      /CID record is immutable/,
    );
    assert.equal((await registry.read.getCID([recordId]))[0], SAMPLE_CID);
  });

  it("stores separate CIDs under separate record IDs", async () => {
    const firstId = `0x${"03".repeat(32)}` as const;
    const secondId = `0x${"04".repeat(32)}` as const;
    await registry.write.storeCID([firstId, SAMPLE_CID]);
    await registry.write.storeCID([secondId, SECOND_CID]);

    const first = await registry.read.getCID([firstId]);
    const second = await registry.read.getCID([secondId]);
    assert.equal(first[0], SAMPLE_CID);
    assert.equal(second[0], SECOND_CID);
    assert.notEqual(first[0], second[0]);
  });
});
