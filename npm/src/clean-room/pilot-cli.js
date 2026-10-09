#!/usr/bin/env node
'use strict';

/**
 * Deliberately separate operator CLI from the decompiler entrypoint.
 * Room A operators run registry-sign and release in a restricted identity.
 * Room B operators run intake, evaluate, and verify-evidence with independent
 * root and worker trust anchors. No automatic authoring or model invocation.
 */
const fs = require('node:fs');
const path = require('node:path');
const { createPrivateKey } = require('node:crypto');
const { readRegular } = require('./isolated-runner');
const { signRegistry, verifyRegistry } = require('./trust-registry');
const { reviewRelease, verifyRelease } = require('./release');
const { createIntake, loadIntake, evaluateIntake } = require('./pilot');
const { verifyAttestation } = require('./attestation');
const { readLedger, ZERO } = require('./evidence-ledger');

function deny(msg) { throw new Error('Clean room operator rejected: ' + msg); }
function json(file, maxBytes) {
  return JSON.parse(readRegular(file, maxBytes).toString('utf8'));
}
function privateKey(file) {
  const buffer = readRegular(file, 8192);
  const mode = fs.statSync(file).mode;
  if ((mode & 0o077) !== 0) deny('private key must be owner-only');
  return createPrivateKey(buffer);
}
function requireCount(args, n, command) {
  if (args.length !== n) deny('Usage: ' + command);
}
function requireRevision(value) {
  if (!/^[1-9][0-9]{0,9}$/.test(value || '')) deny('explicit minimum registry revision required');
  const number = Number(value);
  if (!Number.isSafeInteger(number)) deny('revision exceeds safe integer');
  return number;
}
function outputParent(file) {
  let cursor = path.resolve(path.dirname(file));
  for (;;) {
    const st = fs.lstatSync(cursor);
    if (!st.isDirectory() || st.isSymbolicLink()) deny('unsafe output parent');
    const parent = path.dirname(cursor);
    if (cursor === parent) break;
    cursor = parent;
  }
  if (fs.existsSync(file)) deny('output already exists');
}
function outputFile(file, content) {
  outputParent(file);
  fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content,null,2) + '\n',
    { flag: 'wx', mode: 0o600 });
}
function distinctOutputs(outputs, projectDir = undefined) {
  if (new Set(outputs.map(x => path.resolve(x))).size !== outputs.length) deny('outputs must be distinct');
  for (const file of outputs) {
    if (projectDir) {
      const rel = path.relative(path.resolve(projectDir), path.resolve(file));
      if (rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel))) {
        deny('output cannot be inside implementation workspace');
      }
    }
    outputParent(file);
  }
}
function main(argv) {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case 'registry-sign': {
      requireCount(args, 3, 'registry-sign registry.json root-private.pem registry.signed.json');
      const [input, keyFile, output] = args;
      outputParent(output);
      const signed = signRegistry(json(input, 32*1024), privateKey(keyFile));
      outputFile(output, signed);
      process.stdout.write('Root registry signed at revision ' + signed.registry.revision + '\n');
      return;
    }
    case 'release': {
      if (args.length !== 6 && args.length !== 7) {
        deny('Usage: release approved.json primary-public.pem secondary-private.pem secondary-id release.json --ack-independent [restricted-markers.json]');
      }
      const [file, primaryKeyFile, secondaryKeyFile, secondaryId, dest, ack, markers] = args;
      if (ack !== '--ack-independent') deny('explicit second human reviewer acknowledgement required');
      outputParent(dest);
      const blocklist = markers ? json(markers, 8192) : [];
      const released = reviewRelease(json(file, 24*1024), readRegular(primaryKeyFile, 4096), {
        reviewer: secondaryId, privateKey: privateKey(secondaryKeyFile),
        restrictedMarkers: blocklist,
      });
      outputFile(dest, released);
      process.stdout.write('Second-review release created; export only the signed release\n');
      return;
    }
    case 'verify-release': {
      requireCount(args, 4, 'verify-release release.json signed-registry.json pinned-root.pem minimum-revision');
      const [releaseFile, registryFile, rootPublicKeyFile, minimum] = args;
      const checked = loadIntake({releaseFile,registryFile,rootPublicKeyFile,minimumRevision:requireRevision(minimum)});
      process.stdout.write('Verified two reviewers and registry rev ' + checked.trusted.document.revision +
        '; release ' + checked.verified.releaseSha256 + '\n');
      return;
    }
    case 'intake': {
      requireCount(args, 5, 'intake release.json signed-registry.json pinned-root.pem minimum-revision fresh-implementation-dir');
      const [releaseFile, registryFile, rootPublicKeyFile, minimum, outputDir] = args;
      const result = createIntake({releaseFile,registryFile,rootPublicKeyFile,
        minimumRevision:requireRevision(minimum),outputDir});
      process.stdout.write('Accepted reviewed interface: ' + result.operationCount + ' operations, ' +
        result.vectorCount + ' public vectors; release ' + result.releaseSha256 + '\n');
      return;
    }
    case 'evaluate': {
      requireCount(args, 13, 'evaluate release.json registry.signed.json pinned-root.pem minimum-revision policy.json implementation-dir pinned-image worker-private.pem worker-id evidence.jsonl expected-ledger-head report.json signed-evaluation.json');
      const [releaseFile,registryFile,rootPublicKeyFile,minimum,policyFile,projectDir,
        image,workerPrivateKeyFile,workerId,ledgerFile,expectedHead,reportFile,attestationFile] = args;
      distinctOutputs([reportFile,attestationFile],projectDir);
      const relativeLedger = path.relative(path.resolve(projectDir), path.resolve(ledgerFile));
      if (relativeLedger === '' || (!relativeLedger.startsWith('..' + path.sep) &&
          relativeLedger !== '..' && !path.isAbsolute(relativeLedger))) {
        deny('ledger cannot be inside implementation workspace');
      }
      const result = evaluateIntake({
        releaseFile,registryFile,rootPublicKeyFile,minimumRevision:requireRevision(minimum),
        policyFile,projectDir,image,workerPrivateKeyFile,workerId,ledgerFile,expectedHead,
      });
      outputFile(reportFile,result.report);
      outputFile(attestationFile,result.attestation);
      process.stdout.write('Evaluation ' + result.report.status +
        ', verified vectors ' + result.report.passedVectors + '/' + result.report.vectorCount +
        ', ledger sequence ' + result.checkpoint.sequence +
        ', checkpoint head ' + result.checkpoint.head + '\n');
      if (result.report.status !== 'passed') process.exitCode = 1;
      return;
    }
    case 'verify-evidence': {
      requireCount(args, 6, 'verify-evidence signed-evaluation.json trusted-worker-public.pem worker-id expected-approval-sha ledger.jsonl expected-head');
      const [file,keyFile,workerId,approvalSha,ledgerFile,expectedHead] = args;
      const checked = verifyAttestation(json(file,32*1024),readRegular(keyFile,4096),
        {workerId,approvalSha256:approvalSha});
      const ledger = readLedger(ledgerFile,{expectedHead});
      process.stdout.write('Worker evidence verified: ' + checked.report.status +
        '; ledger seq ' + ledger.sequence + ', head ' + ledger.head + '\n');
      return;
    }
    case 'ledger-check': {
      requireCount(args, 2, 'ledger-check ledger.jsonl externally-recorded-head');
      const state=readLedger(args[0],{expectedHead:args[1]});
      process.stdout.write('Ledger verified: entries ' + state.sequence + ', head ' + state.head + '\n');
      return;
    }
    default:
      deny('Valid commands: registry-sign, release, verify-release, intake, evaluate, verify-evidence, ledger-check');
  }
}
if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (e) { process.stderr.write(e.message + '\n'); process.exitCode=1; }
}
module.exports = { main };
