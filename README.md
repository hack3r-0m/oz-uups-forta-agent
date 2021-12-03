# UUPS Agent

- https://github.com/hack3r-0m/oz-uups-forta-agent

## Description

This agent detects malicious transactions to un-initialized UUPS proxy of openzeppelin. (See https://forum.openzeppelin.com/t/uupsupgradeable-vulnerability-post-mortem/15680/8 for more info regarding vulnerability)

It is important to distinguish between UUPS proxy and Transpararent Upgradable proxy (since they both emit Upgraded event with same signature) to reduce false positives. Hence, agent checks for owner slot which Transpararent Upgradable proxy uses, if slot is empty, it is UUPS proxy.

Agent reports finding with high confidence when both "Upgraded" event & "AdminChanged" are emitted in single transaction as there is very high possibility it is an exploit.

Checking for code size to be 0 will not work as `handleTransaction` is triggered while exploit transaction is in pending state and can result in ambiguity.

## Alerts

- OZ-UUPS-01
  - When Upgraded event is emitted and proxy is idenfied to be UUPS (and not Transparent Upgradable)
  - Type is set to "suspicious"
  - Severity is set to "unknown"
  - metadata includes new implementation along with transaction hash

- OZ-UUPS-02
  - When Upgraded and AdminChanged events are emitted and proxy is idenfied to be UUPS (and not Transparent Upgradable)
  - Type is set to "exploit"
  - Severity is set to "critical"
  - metadata includes new implementation, new owner & transaction hash

## Test Data

- Complete test coverage including false positives and corner cases (see `agent.spec.ts`)

