import { configVariable, defineConfig } from "hardhat/config";
import { createRequire } from "node:module";
import hardhatNodeTestRunner from "@nomicfoundation/hardhat-node-test-runner";
import hardhatViem from "@nomicfoundation/hardhat-viem";

const require = createRequire(import.meta.url);

export default defineConfig({
  plugins: [hardhatNodeTestRunner, hardhatViem],
  networks: {
    localhost: {
      type: "http",
      url: "http://127.0.0.1:8545",
    },
    sepolia: {
      type: "http",
      chainType: "l1",
      chainId: 11155111,
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_DEPLOYER_PRIVATE_KEY")],
    },
  },
  solidity: {
    version: "0.8.34",
    path: require.resolve("solc/soljson.js"),
  },
});
