import {
  TransactionEvent,
  FindingType,
  FindingSeverity,
  Finding,
  EventType,
  Network,
  ethers,
  HandleTransaction
} from 'forta-agent';

import agent, {
  UPGRADED_HASH,
  ADMIN_CHANGED_HASH,
} from "./agent";

describe("Upgraded event is emitted", () => {
  let handleTransaction: HandleTransaction;
  let proxy: string, newImplementation: string;

  const createTxEvent = ({ logs }: any): TransactionEvent => {

    const tx: any = {};
    const receipt: any = {
      logs: logs
    };
    const block: any = {};
    const addresses: any = {};

    return new TransactionEvent(
      EventType.BLOCK,
      Network.MAINNET,
      tx,
      receipt,
      [],
      addresses,
      block
    );
  };

  beforeAll(() => {
    handleTransaction = agent.handleTransaction;
    newImplementation = "0x4cf5e6DE7Dbc33c08aC4404FA34BD6d8daC58c82"
    proxy = "0x0955A73D014F0693aC7B53CFe77706dAb02b3ef9"
  });

  it("should return empty findings when 'Upgraded' event is not emitted", async () => {
    const txEvent = createTxEvent({
      logs: []
    });

    const findings = await handleTransaction(txEvent);
    expect(findings).toStrictEqual([]);
  })

  it("should return suspicous type finding when only 'Upgraded' is emitted", async () => {
    const upgradeEvent = {
      topics: [UPGRADED_HASH],
      address: newImplementation,
      data: ethers.utils.defaultAbiCoder.encode(["address"], [newImplementation])
    };

    const txEvent = createTxEvent({
      logs: [upgradeEvent]
    });

    const findings = await handleTransaction(txEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
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
      })
    ]);
  })

})

describe("Upgraded & AdminChanged event is emitted", () => {
  let handleTransaction: HandleTransaction;
  let oldAdmin: string, newAdmin: string;
  let proxy: string, newImplementation: string;

  const createTxEvent = ({ fromAddress, toAddress, logs, addressMap }: any): TransactionEvent => {

    const tx: any = {
      from: fromAddress,
      to: toAddress
    };
    const receipt: any = {
      logs: logs
    };
    const block: any = {};
    const addresses: any = { addressMap };

    return new TransactionEvent(
      EventType.BLOCK,
      Network.MAINNET,
      tx,
      receipt,
      [],
      addresses,
      block
    );
  };

  beforeAll(() => {
    handleTransaction = agent.handleTransaction;
    oldAdmin = "0x691b35b35e18ad7d0e0cbb97059d2cda0a457c36"
    newAdmin = "0x36ed21f7737e482dDa428D144011987cB94dD072"
    newImplementation = "0x4cf5e6DE7Dbc33c08aC4404FA34BD6d8daC58c82"
    proxy = "0x0955A73D014F0693aC7B53CFe77706dAb02b3ef9"
  });

  it("should return critical severity when both events are emitted", async () => {

    const upgradeEvent = {
      topics: [UPGRADED_HASH],
      address: newImplementation,
      data: ethers.utils.defaultAbiCoder.encode(["address"], [newImplementation])
    };

    const adminChangedEvent = {
      topics: [ADMIN_CHANGED_HASH],
      data: ethers.utils.defaultAbiCoder.encode(["address", "address"], [oldAdmin, newAdmin])
    }

    const txEvent = createTxEvent({
      logs: [upgradeEvent, adminChangedEvent]
    });

    const findings = await handleTransaction(txEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
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
      })
    ]);

  })

  it("should return empty findings when 'AdminChanged' is emitted but 'Upgraded' is not", async () => {
    const adminChangedEvent = {
      topics: [ADMIN_CHANGED_HASH],
      data: ethers.utils.defaultAbiCoder.encode(["address", "address"], [oldAdmin, newAdmin])
    }

    const txEvent = createTxEvent({
      logs: [adminChangedEvent]
    });

    const findings = await handleTransaction(txEvent);

    expect(findings).toStrictEqual([]);

  })

})