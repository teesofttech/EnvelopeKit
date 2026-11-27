import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
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
const browserHtmlPath = path.join(scriptDirectory, 'browser.html');
const dataDirectory = await mkdtemp(path.join(os.tmpdir(), 'envelopekit-jwe-'));
const encoder = new TextEncoder();
const decoder = new TextDecoder();


async function runChromiumExchange() {
  const staticRoot = path.resolve(scriptDirectory);
  const server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
      if (request.method === 'GET' && pathname === '/') {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(await readFile(browserHtmlPath));
        return;
      }
      if (request.method === 'GET' && pathname === '/api-encryption-public.jwk.json') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(await readFile(path.join(dataDirectory, 'api-encryption.public.jwk.json')));
        return;
      }
      if (request.method === 'GET' && pathname === '/api-signing-public.jwk.json') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(await readFile(path.join(dataDirectory, 'api-signing.public.jwk.json')));
        return;
      }
      if (request.method === 'GET' && pathname.startsWith('/node_modules/')) {
        const filePath = path.resolve(staticRoot, `.${pathname}`);
        if (!filePath.startsWith(`${staticRoot}${path.sep}`)) {
          response.writeHead(400).end();
          return;
        }
        response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
        response.end(await readFile(filePath));
        return;
      }
      if (request.method === 'POST' && pathname === '/exchange') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const requestJwe = Buffer.concat(chunks).toString('utf8');
        await writeFile(path.join(dataDirectory, 'request.jwe'), requestJwe);
        runDotnet('process-request');
        response.writeHead(200, { 'content-type': 'application/jose' });
        response.end(await readFile(path.join(dataDirectory, 'response.jwe')));
        return;
      }
      response.writeHead(404).end();
    } catch (error) {
      response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      response.end(String(error));
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Could not start the local browser test server.');
  const browser = await chromium.launch({ headless: true, ...(process.env.ENVELOPEKIT_CHROME_CHANNEL ? { channel: process.env.ENVELOPEKIT_CHROME_CHANNEL } : {}) });
  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error));
    await page.goto(`http://127.0.0.1:${address.port}/`);
    await page.locator('#result[data-status="passed"], #result[data-status="failed"]').waitFor({ timeout: 15000 });
    if (pageErrors.length) throw pageErrors[0];
    const resultStatus = await page.locator('#result').getAttribute('data-status');
    if (resultStatus !== 'passed') throw new Error(await page.locator('#result').textContent());
    console.log('PASS: Chromium WebCrypto exchanged JWE with .NET and verified the signed response.');
  } finally {
    await browser.close();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

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

  await runChromiumExchange();
} finally {
  await rm(dataDirectory, { recursive: true, force: true });
}
