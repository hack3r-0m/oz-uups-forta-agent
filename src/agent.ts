import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType,
  ethers
} from "forta-agent";

import { getEthersProvider } from 'forta-agent';

export const UPGRADED_SIG = "Upgraded(address)";
export const UPGRADED_HASH = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";

export const ADMIN_CHANGED_SIG = "AdminChanged(address,address)";
export const ADMIN_CHANGED_HASH = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f";

export const ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

const handleTransaction: HandleTransaction = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];
  const provider = getEthersProvider()

  let isUUPS: Boolean = false;
  let isAdminChanged: Boolean = false;

  let newImplementation = "";
  let newAdmin = "";

  let finding!: Finding;

  const filterUpgrade = txEvent.filterEvent(
    UPGRADED_SIG
  );

  const filterAdminChanged = txEvent.filterEvent(
    ADMIN_CHANGED_SIG
  );

  if (!filterUpgrade.length) return findings

  for (const log of filterUpgrade) {

    if (log.topics[0] == UPGRADED_HASH) {
      const value = await provider.getStorageAt(log.address, ADMIN_SLOT)
      value == "0x0000000000000000000000000000000000000000000000000000000000000000" ? isUUPS = true : isUUPS = false
      newImplementation = ethers.utils.defaultAbiCoder.decode(["address"], log.data)[0]
    }
  }

  for (const log of filterAdminChanged) {
    if (log.topics[0] == ADMIN_CHANGED_HASH) {
      isAdminChanged = true
      newAdmin = ethers.utils.defaultAbiCoder.decode(["address", "address"], log.data)[1]
    }
  }

  if (isUUPS) {
    finding = {
      name: "UUPS Implementation Upgraded",
      description: "Logic contract serving UUPS proxy by delegatecall has been updated",
      alertId: "OZ-UUPS-01",
      protocol: "unknown",
      everestId: "unknown",
      type: FindingType.Suspicious,
      severity: FindingSeverity.Unknown,
      metadata: {
        newImplementation: newImplementation,
        transactionHash: txEvent.hash
      }
    }
  }

  if (isUUPS && isAdminChanged) {
    finding = {
      name: "UUPS Upgraded & Admin Changed",
      description: "Possibly attacker called initializer to gain admin access and upgrading implementation",
      alertId: "OZ-UUPS-2",
      protocol: "unknown",
      everestId: "unknown",
      type: FindingType.Exploit,
      severity: FindingSeverity.Critical,
      metadata: {
        newImplementation: newImplementation,
        newAdmin: newAdmin,
        transactionHash: txEvent.hash
      }
    }
  }

  findings.push(
    Finding.fromObject(finding)
  )

  return findings;
};

export default { handleTransaction };
