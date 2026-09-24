import { createHash } from "node:crypto";
import { canonicalJson as canonical } from "@red-cup-engineering/json-services-section/canonical-json";

const CREDENTIAL_FIELDS = new Set(["authorization", "apikey", "apikeyid", "apisecret", "clientid", "clientsecret", "secret", "token", "accesstoken", "refreshtoken", "privatekey", "password"]);
const credentialField = (key) => { const normalized = String(key).toLowerCase().replace(/[-_\s]/gu, ""); return [...CREDENTIAL_FIELDS, "apisecretkey"].some((suffix) => normalized === suffix || normalized.endsWith(suffix)); };
function clean(value, seen = new Set()) {
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return null;
  seen.add(value);
  if (Array.isArray(value)) return value.map((member) => clean(member, seen));
  return Object.fromEntries(Object.entries(value).filter(([key]) => !credentialField(key)).map(([key, member]) => [key, clean(member, seen)]));
}
const TRADING_HOST = Object.freeze({ paper: "paper-api.alpaca.markets", live: "api.alpaca.markets" });
const PRODUCT_KINDS = Object.freeze({ "alpaca-connect": new Set(["alpaca-oauth"]), "alpaca-broker": new Set(["alpaca-broker-api-key", "alpaca-broker-client"]), "alpaca-trading-paper": new Set(["alpaca-trading-api-key"]), "alpaca-trading-live": new Set(["alpaca-trading-api-key-live"]) });
const CREDENTIAL_KIND = Object.freeze({ paper: "alpaca-trading-api-key", live: "alpaca-trading-api-key-live" });
const capitalize = (mode) => `${mode[0].toUpperCase()}${mode.slice(1)}`;
function originFor(mode, url) {
  let parsed; try { parsed = new URL(url); } catch { throw new TypeError(`${mode}-trading-host-refused`); }
  if (parsed.protocol !== "https:" || parsed.hostname !== TRADING_HOST[mode] || parsed.port !== "" || parsed.username || parsed.password) throw new TypeError(`${mode}-trading-host-refused`);
  return parsed;
}
const instant = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw new TypeError(`${label}-invalid`); return parsed; };
function operationFor(mode, method, parsed) {
  if (parsed.hash) throw new TypeError(`${mode}-trading-operation-refused`);
  const query = [...parsed.searchParams.entries()], noQuery = query.length === 0;
  if (method === "GET" && parsed.pathname === "/v2/account" && noQuery) return { scope: "account:read", effect: "read" };
  if (method === "GET" && parsed.pathname === "/v2/positions" && noQuery) return { scope: "positions:read", effect: "read" };
  if (method === "POST" && parsed.pathname === "/v2/orders" && noQuery) return { scope: `orders:${mode}`, effect: "place" };
  if (method === "DELETE" && /^\/v2\/orders\/[^/]+$/u.test(parsed.pathname) && noQuery) return { scope: `orders:${mode}`, effect: "cancel", orderId: decodeURIComponent(parsed.pathname.slice("/v2/orders/".length)) };
  if (method === "GET" && parsed.pathname === "/v2/orders:by_client_order_id" && query.length === 1 && query[0][0] === "client_order_id" && query[0][1].length > 0 && query[0][1].length <= 128) return { scope: "orders:read", effect: "read" };
  if (method === "GET" && parsed.pathname === "/v2/account/activities" && query.length === 1 && query[0][0] === "activity_types" && query[0][1].length > 0) return { scope: "activities:read", effect: "read" };
  throw new TypeError(`${mode}-trading-operation-refused`);
}

const clientOrderIdFor = (mode, contractId, intentId) => `${mode}-${createHash("sha256").update(`${contractId}:${intentId}`).digest("hex").slice(0, 48)}`;
function validateOrderAuthorization(mode, { authorization, reference, currentGrant, operation, body, nowMs }) {
  const { contract, authorityGrant, intent, revocation } = authorization ?? {};
  if (typeof reference !== "string" || reference.trim() === "" || intent?.id !== reference || intent.type !== "AggressiveBrokerageOrderIntent") throw new TypeError(`exact-${mode}-order-authorization-required`);
  if (contract?.type !== "PrincipalBrokerageServiceContract" || authorityGrant?.type !== "RevocableBrokerageAuthorityGrant" || contract.id !== intent.contract || authorityGrant.id !== currentGrant.id || authorityGrant.principalContract !== contract.id || authorityGrant.revoked !== false || revocation?.effective === true) throw new TypeError(`${mode}-order-authorization-binding-refused`);
  if (["credentialReference", "principal", "accountReference", "venue", "adapter", "validUntil"].some((field) => authorityGrant[field] !== currentGrant[field]) || canonical(authorityGrant.scopes) !== canonical(currentGrant.scopes)) throw new TypeError(`${mode}-order-authoritative-grant-drift-refused`);
  if (contract.venue !== `alpaca-trading-${mode}` || authorityGrant.venue !== `alpaca-trading-${mode}` || authorityGrant.adapter !== `alpaca-trading-${mode}` || contract.principal !== authorityGrant.principal || contract.accountReference !== authorityGrant.accountReference || !contract.scopes?.includes(operation.scope) || !authorityGrant.scopes?.includes(operation.scope)) throw new TypeError(`${mode}-order-authorization-binding-refused`);
  const contractExpiry = instant(contract.validUntil, `${mode}-contract-expiry`), grantExpiry = instant(authorityGrant.validUntil, `${mode}-authority-expiry`);
  if (nowMs >= contractExpiry || nowMs >= grantExpiry) throw new TypeError(`${mode}-order-authorization-expired`);
  if (![intent.notional, intent.maximumLoss, contract.risk?.maximumOrderNotional, contract.risk?.maximumLossAmount].every(Number.isFinite) || intent.notional > contract.risk.maximumOrderNotional || intent.maximumLoss > contract.risk.maximumLossAmount) throw new TypeError(`${mode}-order-risk-limit-refused`);
  const allowed = { symbol: intent.symbol, side: intent.side, notional: intent.notional, type: "market", time_in_force: "day", client_order_id: clientOrderIdFor(mode, contract.id, intent.id) };
  if (canonical(body) !== canonical(allowed)) throw new TypeError(`${mode}-order-body-drift-refused`);
}
function validateCancellationAuthorization(mode, { authorization, reference, currentGrant, operation, nowMs }) {
  if (typeof reference !== "string" || reference.trim() === "" || authorization?.id !== reference || authorization.type !== `${capitalize(mode)}OrderCancellationAuthorization` || authorization.authorityGrant !== currentGrant.id || authorization.orderId !== operation.orderId || authorization.revoked !== false) throw new TypeError(`exact-${mode}-cancellation-authorization-required`);
  if (nowMs >= instant(authorization.validUntil, `${mode}-cancellation-expiry`)) throw new TypeError(`${mode}-cancellation-authorization-expired`);
}

export function createBrokerageAuthorityCustody({ authorityCustody, transport, resolveAuthorityGrant, resolvePaperOperationAuthorization, resolvePaperObservationAuthorization, resolveLiveOperationAuthorization, fetchImpl = fetch, brokerTokenEndpoint = "https://authx.alpaca.markets/v1/oauth2/token", clock = () => new Date().toISOString() }) {
  if (typeof transport !== "function") throw new TypeError("custody-owned-transport-required");
  if (!["store", "retrieve", "revoke"].every((method) => typeof authorityCustody?.[method] === "function")) throw new TypeError("authority-custody-actuator-required");
  return Object.freeze({
    async authorizedRequest({ credentialReference, authorityGrantReference, observationAuthorizationReference, operationAuthorizationReference, product, scope, method, url, body }) {
      let record, effectiveScope = scope;
      if (!PRODUCT_KINDS[product]) throw new TypeError("unknown-brokerage-product-refused");
      const requestTime = clock(), requestTimeMs = instant(requestTime, "custody-clock");
      if (product === "alpaca-trading-paper" || product === "alpaca-trading-live") {
        const mode = product === "alpaca-trading-paper" ? "paper" : "live";
        const operation = operationFor(mode, method, originFor(mode, url));
        if (mode === "paper" && typeof observationAuthorizationReference === "string") {
          if (typeof resolvePaperObservationAuthorization !== "function" || authorityGrantReference !== undefined || operationAuthorizationReference !== undefined || credentialReference !== undefined || scope !== undefined || operation.effect !== "read" || !["account:read", "positions:read"].includes(operation.scope)) throw new TypeError("paper-observation-authorization-refused");
          const authorization = await resolvePaperObservationAuthorization(observationAuthorizationReference);
          if (authorization?.id !== observationAuthorizationReference || authorization.type !== "PrincipalPaperAccountObservationAuthorization" || authorization.revoked !== false || authorization.venue !== product || !authorization.scopes?.includes(operation.scope) || requestTimeMs >= instant(authorization.validUntil, "paper-observation-expiry")) throw new TypeError("current-paper-observation-authorization-required");
          record = await authorityCustody.retrieve(authorization.credentialReference);
          if (!record || record.kind !== CREDENTIAL_KIND[mode] || record.environment !== mode || record.venue !== product || record.accountReference !== authorization.accountAlias) throw new TypeError("paper-observation-credential-binding-refused");
          effectiveScope = operation.scope; credentialReference = authorization.credentialReference;
        } else {
        if (mode === "live" && observationAuthorizationReference !== undefined) throw new TypeError("live-observation-shortcut-not-supported");
        const resolveOperationAuthorization = mode === "paper" ? resolvePaperOperationAuthorization : resolveLiveOperationAuthorization;
        if (typeof resolveAuthorityGrant !== "function") throw new TypeError(`${mode}-authority-grant-resolver-required`);
        if (credentialReference !== undefined || scope !== undefined || typeof authorityGrantReference !== "string" || authorityGrantReference.trim() === "") throw new TypeError(`${mode}-authority-reference-only-required`);
        const grant = await resolveAuthorityGrant(authorityGrantReference);
        if (grant?.id !== authorityGrantReference || grant.type !== "RevocableBrokerageAuthorityGrant" || grant.revoked !== false) throw new TypeError(`current-${mode}-authority-grant-required`);
        const grantExpiry = instant(grant.validUntil, `${mode}-authority-expiry`);
        if (requestTimeMs >= grantExpiry) throw new TypeError(`${mode}-authority-expired`);
        record = await authorityCustody.retrieve(grant.credentialReference);
        if (!record) throw new TypeError("credential-reference-revoked-or-unknown");
        if (record.kind !== CREDENTIAL_KIND[mode] || record.environment !== mode || record.venue !== product || grant.principal !== record.principal || grant.accountReference !== record.accountReference || grant.venue !== record.venue || grant.adapter !== product) throw new TypeError(`${mode}-authority-binding-mismatch`);
        effectiveScope = operation.scope;
        if (!grant.scopes?.includes(effectiveScope)) throw new TypeError(`${mode}-authority-operation-scope-refused`);
        if (operation.effect !== "read") {
          if (typeof resolveOperationAuthorization !== "function") throw new TypeError(`${mode}-operation-authorization-resolver-required`);
          if (typeof operationAuthorizationReference !== "string" || operationAuthorizationReference.trim() === "") throw new TypeError(`exact-${mode}-operation-authorization-required`);
          const authorization = await resolveOperationAuthorization(operationAuthorizationReference);
          if (operation.effect === "place") validateOrderAuthorization(mode, { authorization, reference: operationAuthorizationReference, currentGrant: grant, operation, body, nowMs: requestTimeMs });
          else validateCancellationAuthorization(mode, { authorization, reference: operationAuthorizationReference, currentGrant: grant, operation, nowMs: requestTimeMs });
        } else if (operationAuthorizationReference !== undefined) throw new TypeError(`${mode}-read-operation-authorization-refused`);
        credentialReference = grant.credentialReference;
        }
      } else {
        record = await authorityCustody.retrieve(credentialReference);
        if (!record) throw new TypeError("credential-reference-revoked-or-unknown");
        if (!PRODUCT_KINDS[product].has(record.kind)) throw new TypeError("credential-product-mismatch");
      }
      if (record.credential.expiresAt && requestTimeMs >= instant(record.credential.expiresAt, "credential-expiry")) throw new TypeError("custodied-access-token-expired");
      let headers;
      if (record.kind === "alpaca-oauth") headers = { Authorization: `Bearer ${record.credential.accessToken}` };
      else if (["alpaca-broker-api-key", "alpaca-trading-api-key", "alpaca-trading-api-key-live"].includes(record.kind)) headers = { "APCA-API-KEY-ID": record.credential.apiKeyId, "APCA-API-SECRET-KEY": record.credential.apiSecret };
      else {
        const cached = record.credential.cachedToken;
        if (!cached || requestTimeMs >= instant(cached.expiresAt, "cached-token-expiry")) {
          const response = await fetchImpl(brokerTokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "client_credentials", client_id: record.credential.clientId, client_secret: record.credential.clientSecret }) });
          if (!response?.ok) throw new TypeError("alpaca-broker-token-issuance-refused"); const issued = await response.json();
          if (!issued?.access_token || !Number.isFinite(Number(issued.expires_in))) throw new TypeError("alpaca-broker-token-response-invalid");
          record.credential.cachedToken = { accessToken: issued.access_token, expiresAt: new Date(requestTimeMs + Math.max(1, Number(issued.expires_in) - 30) * 1000).toISOString() };
        }
        headers = { Authorization: `Bearer ${record.credential.cachedToken.accessToken}` };
      }
      const response = await transport({ method, url, headers, body, scope: effectiveScope });
      if (!Number.isInteger(response?.status)) throw new TypeError("custody-transport-response-invalid");
      return Object.freeze({ status: response.status, headers: clean(response.headers ?? {}), body: clean(response.body),
        authorityCustodyReceipt: { type: "CustodiedVenueRequestReceipt", credentialReference, authorityGrantReference: authorityGrantReference ?? null, product, scope: effectiveScope, secretBytesReturned: false, performedAt: requestTime } });
    },
  });
}
