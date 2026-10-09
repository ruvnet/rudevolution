#!/usr/bin/env node
'use strict';

/** Room A and Room B are separate invocations, ideally isolated OS identities. */
const fs = require('node:fs');
const path = require('node:path');
const { validateSpec, approveSpec, verifyApproved, scaffoldFiles } = require('./index');
const { sandboxTest } = require('./isolated-runner');

function assertNoSymlinkAncestors(filename) {
  let current = path.resolve(path.dirname(filename));
  for (;;) {
    const st = fs.lstatSync(current);
    if (!st.isDirectory() || st.isSymbolicLink()) throw Error('A path parent is not a regular directory');
    const up = path.dirname(current);
    if (up === current) break;
    current = up;
  }
}
function readBounded(filename, limit) {
  assertNoSymlinkAncestors(filename);
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw Error('Input must be a regular, nonsymlink file within its size limit');
  return fs.readFileSync(filename, 'utf8');
}
function readJson(filename, limit) { return JSON.parse(readBounded(filename, limit)); }
function readPrivateKey(filename) {
  const stat = fs.lstatSync(filename);
  if ((stat.mode & 0o077) !== 0) throw Error('Private key must not be accessible to group or other users');
  return readBounded(filename, 8192);
}
function requireArgs(actual, count, usage) {
  if (actual.length !== count) throw Error(`Usage: ${usage}`);
}
function safeOutput(filename, content, mode = 0o600) {
  fs.writeFileSync(filename, content, { flag: 'wx', mode });
}
function verifyOutputParent(filename) {
  assertNoSymlinkAncestors(filename);
}
function main(argv) {
  const [command, ...args] = argv;
  switch (command) {
    case 'validate': {
      requireArgs(args, 1, 'node npm/src/clean-room/cli.js validate spec.json');
      const spec = readJson(args[0], 16 * 1024);
      validateSpec(spec);
      process.stdout.write(`Valid interface-only specification: ${spec.operations.length} operations, ${spec.vectors.length} vectors\n`);
      return;
    }
    case 'approve': {
      requireArgs(args, 6, 'node npm/src/clean-room/cli.js approve spec.json room-a-private.pem reviewer approved.json receipt.json --ack-reviewed');
      const [source, keyFile, reviewer, destination, receiptFile, ack] = args;
      if (ack !== '--ack-reviewed') throw Error('Explicit human review acknowledgement is required');
      if (path.resolve(destination) === path.resolve(receiptFile)) throw Error('Receipt and artifact paths must differ');
      verifyOutputParent(destination);
      verifyOutputParent(receiptFile);
      // Fail before reading the signing key if either output already exists.
      if (fs.existsSync(destination) || fs.existsSync(receiptFile)) throw Error('Output already exists; refusing overwrite');
      const spec = readJson(source, 16 * 1024);
      const privateKey = readPrivateKey(keyFile);
      const { artifact, receipt } = approveSpec(spec, { reviewer, privateKey });
      // Room B receives only approved.json plus an independently pinned public key.
      // The room-A receipt remains private, outside the room-B export directory.
      let approvalWritten = false;
      try {
        safeOutput(destination, `${JSON.stringify(artifact, null, 2)}\n`);
        approvalWritten = true;
        safeOutput(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
      } catch (err) {
        if (approvalWritten) fs.unlinkSync(destination);
        throw err;
      }
      process.stdout.write(`Approved reviewed contract: ${receipt.specSha256}\n`);
      return;
    }
    case 'verify': {
      requireArgs(args, 2, 'node npm/src/clean-room/cli.js verify approved.json room-b-trusted-public.pem');
      const signed = readJson(args[0], 24 * 1024);
      const key = readBounded(args[1], 8192);
      const v = verifyApproved(signed, key);
      process.stdout.write(`Verified: ${v.approvalSha256}; reviewer=${v.reviewer}; key=${v.publicKeyFingerprint}\n`);
      return;
    }
    case 'scaffold': {
      requireArgs(args, 3, 'node npm/src/clean-room/cli.js scaffold approved.json room-b-trusted-public.pem NEW_OUTPUT_DIRECTORY');
      const [approvalFile, publicKeyFile, dir] = args;
      const signed = readJson(approvalFile, 24 * 1024);
      const key = readBounded(publicKeyFile, 8192);
      const files = scaffoldFiles(signed, key); // complete signature and schema verification before I/O
      verifyOutputParent(dir);
      fs.mkdirSync(dir, { recursive: false, mode: 0o700 }); // fail closed for an existing directory
      for (const [filename, contents] of Object.entries(files)) safeOutput(path.join(dir, filename), contents, 0o600);
      process.stdout.write(`Created isolated implementation scaffold with ${signed.spec.operations.length} operations\n`);
      return;
    }
    case 'sandbox-test': {
      requireArgs(args, 6, 'node npm/src/clean-room/cli.js sandbox-test approved.json trusted-public.pem room-b-policy.json independent-project IMAGE@sha256:DIGEST report.json');
      const [approvedFile, publicKeyFile, policyFile, projectDir, image, reportFile] = args;
      const project = path.resolve(projectDir);
      const output = path.resolve(reportFile);
      const relative = path.relative(project, output);
      if (relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative))) {
        throw Error('Room B test report must be stored outside the implementation project');
      }
      verifyOutputParent(reportFile);
      if (fs.existsSync(reportFile)) throw Error('Refusing to overwrite a previous evaluation report');
      const report = sandboxTest({ approvedFile, publicKeyFile, policyFile, projectDir, image });
      safeOutput(reportFile, JSON.stringify(report, null, 2) + '\n');
      process.stdout.write('Room B isolated test: ' + report.status + ', approved vectors=' + report.vectorCount + '\n');
      if (report.status !== 'passed') process.exitCode = 1;
      return;
    }
    default:
      throw Error('Usage: cli.js <validate|approve|verify|scaffold|sandbox-test> ...');
  }
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (err) { process.stderr.write(`${err.message}\n`); process.exitCode = 1; }
}
module.exports = { main };
