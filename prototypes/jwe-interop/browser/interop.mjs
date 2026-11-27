import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CompactEncrypt,
  compactDecrypt,
  compactVerify,
  exportJWK,
  generateKeyPair,
  importJWK,
} from 'jose';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '../../..');
const dotnetProject = path.join(scriptDirectory, '../dotnet/JweInterop.csproj');
const dataDirectory = await mkdtemp(path.join(os.tmpdir(), 'envelopekit-jwe-'));
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function runDotnet(command) {
  const env = { ...process.env, ENVELOPEKIT_SPIKE_DATA: dataDirectory };
  const restoreArgs = ['restore', dotnetProject];
  if (env.ENVELOPEKIT_NUGET_SOURCE) {
    restoreArgs.push('--source', env.ENVELOPEKIT_NUGET_SOURCE);
  }
  execFileSync('dotnet', restoreArgs, { cwd: repositoryRoot, env, stdio: 'inherit' });
  execFileSync('dotnet', ['run', '--no-restore', '--project', dotnetProject, '--configuration', 'Release', '--', command], {
    cwd: repositoryRoot,
    env,
    stdio: 'inherit',
  });
}

try {
  runDotnet('setup');

  const apiEncryptionJwk = JSON.parse(await readFile(path.join(dataDirectory, 'api-encryption.public.jwk.json'), 'utf8'));
  const apiSigningJwk = JSON.parse(await readFile(path.join(dataDirectory, 'api-signing.public.jwk.json'), 'utf8'));
  const apiEncryptionKey = await importJWK(apiEncryptionJwk, 'ECDH-ES');
  const apiSigningKey = await importJWK(apiSigningJwk, 'ES256');

  const responseKeyPair = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const responsePublicJwk = {
    ...(await exportJWK(responseKeyPair.publicKey)),
    kid: 'client-response-1',
    use: 'enc',
  };
  const responsePrivateJwk = await exportJWK(responseKeyPair.privateKey);
  const requestEnvelope = {
    version: 1,
    requestId: 'interop-request-001',
    responsePublicKey: responsePublicJwk,
    body: { message: 'browser request to .NET' },
  };
  const requestJwe = await new CompactEncrypt(encoder.encode(JSON.stringify(requestEnvelope)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: apiEncryptionJwk.kid })
    .encrypt(apiEncryptionKey);

  await writeFile(path.join(dataDirectory, 'request.jwe'), requestJwe);
  await writeFile(path.join(dataDirectory, 'response.private.jwk.json'), JSON.stringify(responsePrivateJwk));
  runDotnet('process-request');

  const responseJwe = await readFile(path.join(dataDirectory, 'response.jwe'), 'utf8');
  const responsePrivateKey = await importJWK(responsePrivateJwk, 'ECDH-ES');
  const { plaintext: signedResponseBytes, protectedHeader: responseHeader } = await compactDecrypt(responseJwe, responsePrivateKey);
  assert.equal(responseHeader.alg, 'ECDH-ES');
  assert.equal(responseHeader.enc, 'A256GCM');

  const signedResponse = decoder.decode(signedResponseBytes);
  const { payload, protectedHeader: signatureHeader } = await compactVerify(signedResponse, apiSigningKey);
  assert.equal(signatureHeader.alg, 'ES256');
  assert.equal(signatureHeader.kid, apiSigningJwk.kid);

  const responseEnvelope = JSON.parse(decoder.decode(payload));
  assert.equal(responseEnvelope.requestId, requestEnvelope.requestId);
  assert.equal(responseEnvelope.body.echoed.message, requestEnvelope.body.message);
  assert.equal(responseEnvelope.body.accepted, true);

  const responseParts = responseJwe.split('.');
  responseParts[4] = `${responseParts[4][0] === 'A' ? 'B' : 'A'}${responseParts[4].slice(1)}`;
  await assert.rejects(compactDecrypt(responseParts.join('.'), responsePrivateKey));

  console.log('PASS: browser-compatible JOSE created a JWE request that .NET decrypted.');
  console.log('PASS: .NET signed the response with JWS, encrypted it with JWE, and the browser-compatible JOSE client verified both.');
  console.log('PASS: changing the response authentication tag caused decryption to fail.');
} finally {
  await rm(dataDirectory, { recursive: true, force: true });
}
