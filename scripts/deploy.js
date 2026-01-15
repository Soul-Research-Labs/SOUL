const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  // Track deployed addresses
  const deployed = {};

  // 1. Deploy Groth16VerifierBLS12381
  console.log("\n1. Deploying Groth16VerifierBLS12381...");
  const Verifier = await ethers.getContractFactory(
    "contracts/core/Groth16VerifierBLS12381.sol:Groth16VerifierBLS12381"
  );
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  deployed.verifier = await verifier.getAddress();
  console.log("   Groth16VerifierBLS12381 deployed to:", deployed.verifier);

  // 2. Deploy ConfidentialStateContainer
  console.log("\n2. Deploying ConfidentialStateContainer...");
  const StateContainer = await ethers.getContractFactory(
    "contracts/core/ConfidentialStateContainerV2.sol:ConfidentialStateContainer"
  );
  const stateContainer = await StateContainer.deploy(deployed.verifier);
  await stateContainer.waitForDeployment();
  deployed.stateContainer = await stateContainer.getAddress();
  console.log("   ConfidentialStateContainer deployed to:", deployed.stateContainer);

  // 3. Deploy CrossChainProofHub
  console.log("\n3. Deploying CrossChainProofHub...");
  const minimumStake = ethers.parseEther("10"); // 10 ETH minimum stake
  const ProofHub = await ethers.getContractFactory("CrossChainProofHub");
  const proofHub = await ProofHub.deploy(deployed.verifier, minimumStake);
  await proofHub.waitForDeployment();
  deployed.proofHub = await proofHub.getAddress();
  console.log("   CrossChainProofHub deployed to:", deployed.proofHub);

  // 4. Deploy PILAtomicSwap
  console.log("\n4. Deploying PILAtomicSwap...");
  const AtomicSwap = await ethers.getContractFactory("PILAtomicSwap");
  const atomicSwap = await AtomicSwap.deploy(deployer.address); // Deployer as fee collector
  await atomicSwap.waitForDeployment();
  deployed.atomicSwap = await atomicSwap.getAddress();
  console.log("   PILAtomicSwap deployed to:", deployed.atomicSwap);

  // 5. Deploy PILCompliance
  console.log("\n5. Deploying PILCompliance...");
  const Compliance = await ethers.getContractFactory("PILCompliance");
  const compliance = await Compliance.deploy();
  await compliance.waitForDeployment();
  deployed.compliance = await compliance.getAddress();
  console.log("   PILCompliance deployed to:", deployed.compliance);

  // 6. Deploy PILOracle
  console.log("\n6. Deploying PILOracle...");
  const Oracle = await ethers.getContractFactory("PILOracle");
  const oracle = await Oracle.deploy();
  await oracle.waitForDeployment();
  deployed.oracle = await oracle.getAddress();
  console.log("   PILOracle deployed to:", deployed.oracle);

  // 7. Deploy RateLimiter
  console.log("\n7. Deploying RateLimiter...");
  const RateLimiter = await ethers.getContractFactory("RateLimiter");
  const rateLimiter = await RateLimiter.deploy();
  await rateLimiter.waitForDeployment();
  deployed.rateLimiter = await rateLimiter.getAddress();
  console.log("   RateLimiter deployed to:", deployed.rateLimiter);

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(JSON.stringify(deployed, null, 2));
  console.log("=".repeat(60));

  // Write to file for later reference
  const fs = require("fs");
  const networkName = (await ethers.provider.getNetwork()).name;
  const deploymentFile = `deployments/${networkName}_${Date.now()}.json`;
  
  // Ensure deployments directory exists
  if (!fs.existsSync("deployments")) {
    fs.mkdirSync("deployments");
  }
  
  fs.writeFileSync(
    deploymentFile,
    JSON.stringify({
      network: networkName,
      deployer: deployer.address,
      timestamp: new Date().toISOString(),
      contracts: deployed
    }, null, 2)
  );
  console.log(`\nDeployment info saved to: ${deploymentFile}`);

  return deployed;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
