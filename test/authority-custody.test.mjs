import assert from "node:assert/strict";
import test from "node:test";
import { createBrokerageAuthorityCustody } from "../src/authority-custody.mjs";
import { createAlpacaConnectOAuthBroker } from "../src/alpaca-connect-oauth.mjs";

const now = "2030-01-01T00:00:00.000Z";
const paperCredential = Object.freeze({
  kind: "alpaca-trading-api-key", environment: "paper", venue: "alpaca-trading-paper",
  accountReference: "paper-account", principal: "principal-1",
  credential: { apiKeyId: "key-id", apiSecret: "secret-not-to-export" },
});
const paperObservation = Object.freeze({
  id: "observation-1", type: "PrincipalPaperAccountObservationAuthorization", revoked: false,
  venue: "alpaca-trading-paper", accountAlias: "paper-account", credentialReference: "credential-1",
  scopes: ["account:read", "positions:read"], validUntil: "2031-01-01T00:00:00.000Z",
});

test("paper observation custody permits only authorized reads and never returns credentials", async () => {
  const calls = [];
  const custody = createBrokerageAuthorityCustody({
    authorityCustody: { store() {}, revoke() {}, async retrieve(reference) { return reference === "credential-1" ? structuredClone(paperCredential) : undefined; } },
    async transport(request) { calls.push(request); return { status: 200, headers: { authorization: "hidden", "x-request-id": "request-1" }, body: { equity: "100", apiSecret: "hidden" } }; },
    async resolvePaperObservationAuthorization(reference) { return reference === "observation-1" ? paperObservation : undefined; },
    clock: () => now,
  });
  const response = await custody.authorizedRequest({ product: "alpaca-trading-paper", observationAuthorizationReference: "observation-1", method: "GET", url: "https://paper-api.alpaca.markets/v2/account" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].scope, "account:read");
  assert.equal(calls[0].headers["APCA-API-SECRET-KEY"], "secret-not-to-export");
  assert.deepEqual(response.headers, { "x-request-id": "request-1" });
  assert.deepEqual(response.body, { equity: "100" });
  assert.equal(response.authorityCustodyReceipt.secretBytesReturned, false);
  assert.equal(response.authorityCustodyReceipt.credentialReference, "credential-1");
});

test("observation authorization cannot place a paper order", async () => {
  let transported = false;
  const custody = createBrokerageAuthorityCustody({
    authorityCustody: { store() {}, revoke() {}, async retrieve() { return structuredClone(paperCredential); } },
    async transport() { transported = true; },
    async resolvePaperObservationAuthorization() { return paperObservation; },
    clock: () => now,
  });
  await assert.rejects(
    custody.authorizedRequest({ product: "alpaca-trading-paper", observationAuthorizationReference: "observation-1", method: "POST", url: "https://paper-api.alpaca.markets/v2/orders", body: {} }),
    /paper-observation-authorization-refused/,
  );
  assert.equal(transported, false);
});

test("live execution rejects an expired grant before transport", async () => {
  let transported = false;
  const custody = createBrokerageAuthorityCustody({
    authorityCustody: { store() {}, revoke() {}, async retrieve() { return undefined; } },
    async transport() { transported = true; },
    async resolveAuthorityGrant() { return { id: "grant-1", type: "RevocableBrokerageAuthorityGrant", revoked: false, validUntil: "2029-01-01T00:00:00.000Z", scopes: ["orders:live"] }; },
    clock: () => now,
  });
  await assert.rejects(
    custody.authorizedRequest({ product: "alpaca-trading-live", authorityGrantReference: "grant-1", method: "POST", url: "https://api.alpaca.markets/v2/orders", body: {} }),
    /live-authority-expired/,
  );
  assert.equal(transported, false);
});

test("OAuth boundary refuses mismatched state and stores exchanged tokens only in custody", async () => {
  let fetches = 0;
  const stored = [];
  const broker = createAlpacaConnectOAuthBroker({
    clientId: "client", clientSecret: "secret", redirectUri: "https://example.test/callback",
    custody: { async store(record) { stored.push(record); return { reference: "stored-1" }; } },
    async fetchImpl() { fetches += 1; return { ok: true, async json() { return { access_token: "access", refresh_token: "refresh", expires_in: 60 }; } }; },
  });
  assert.throws(() => broker.authorizationUrl({ state: "short" }), /oauth-state-environment-or-scope-refused/);
  await assert.rejects(broker.exchangeAuthorizationCode({ code: "code", state: "wrong", expectedState: "right", principal: "principal-1" }), /oauth-state-mismatch-or-code-absent/);
  assert.equal(fetches, 0);
  const receipt = await broker.exchangeAuthorizationCode({ code: "code", state: "x".repeat(32), expectedState: "x".repeat(32), principal: "principal-1" });
  assert.deepEqual(receipt, { reference: "stored-1" });
  assert.equal(stored.length, 1);
  assert.equal(stored[0].secret.credential.accessToken, "access");
});
