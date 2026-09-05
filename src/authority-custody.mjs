import { createHash } from "node:crypto";

const CREDENTIAL_FIELDS = new Set(["authorization", "apikey", "apikeyid", "apisecret", "clientid", "clientsecret", "secret", "token", "accesstoken", "refreshtoken", "privatekey", "password"]);
const credentialField = (key) => { const normalized = String(key).toLowerCase().replace(/[-_\s]/gu, ""); return [...CREDENTIAL_FIELDS, "apisecretkey"].some((suffix) => normalized === suffix || normalized.endsWith(suffix)); };
function clean(value, seen = new Set()) {
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return null;
  seen.add(value);
  if (Array.isArray(value)) return value.map((member) => clean(member, seen));
  return Object.fromEntries(Object.entries(value).filter(([key]) => !credentialField(key)).map(([key, member]) => [key, clean(member, seen)]));
}
const PAPER_TRADING_HOST = "paper-api.alpaca.markets";
const LIVE_TRADING_HOST = "api.alpaca.markets";
const PRODUCT_KINDS = Object.freeze({ "alpaca-connect": new Set(["alpaca-oauth"]), "alpaca-broker": new Set(["alpaca-broker-api-key", "alpaca-broker-client"]), "alpaca-trading-paper": new Set(["alpaca-trading-api-key"]), "alpaca-trading-live": new Set(["alpaca-trading-api-key-live"]) });
function paperOrigin(url) {
  let parsed; try { parsed = new URL(url); } catch { throw new TypeError("paper-trading-host-refused"); }
  if (parsed.protocol !== "https:" || parsed.hostname !== PAPER_TRADING_HOST || parsed.port !== "" || parsed.username || parsed.password) throw new TypeError("paper-trading-host-refused");
  return parsed;
}
function liveOrigin(url) {
  let parsed; try { parsed = new URL(url); } catch { throw new TypeError("live-trading-host-refused"); }
  if (parsed.protocol !== "https:" || parsed.hostname !== LIVE_TRADING_HOST || parsed.port !== "" || parsed.username || parsed.password) throw new TypeError("live-trading-host-refused");
  return parsed;
}
const instant = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw new TypeError(`${label}-invalid`); return parsed; };
function paperOperation(method, parsed) {
  if (parsed.hash) throw new TypeError("paper-trading-operation-refused");
  const query = [...parsed.searchParams.entries()], noQuery = query.length === 0;
  if (method === "GET" && parsed.pathname === "/v2/account" && noQuery) return { scope: "account:read", effect: "read" };
  if (method === "GET" && parsed.pathname === "/v2/positions" && noQuery) return { scope: "positions:read", effect: "read" };
  if (method === "POST" && parsed.pathname === "/v2/orders" && noQuery) return { scope: "orders:paper", effect: "place" };
  if (method === "DELETE" && /^\/v2\/orders\/[^/]+$/u.test(parsed.pathname) && noQuery) return { scope: "orders:paper", effect: "cancel", orderId: decodeURIComponent(parsed.pathname.slice("/v2/orders/".length)) };
  if (method === "GET" && parsed.pathname === "/v2/orders:by_client_order_id" && query.length === 1 && query[0][0] === "client_order_id" && query[0][1].length > 0 && query[0][1].length <= 128) return { scope: "orders:read", effect: "read" };
  if (method === "GET" && parsed.pathname === "/v2/account/activities" && query.length === 1 && query[0][0] === "activity_types" && query[0][1].length > 0) return { scope: "activities:read", effect: "read" };
  throw new TypeError("paper-trading-operation-refused");
}
function liveOperation(method, parsed) {
  if (parsed.hash) throw new TypeError("live-trading-operation-refused");
  const query = [...parsed.searchParams.entries()], noQuery = query.length === 0;
  if (method === "GET" && parsed.pathname === "/v2/account" && noQuery) return { scope: "account:read", effect: "read" };
  if (method === "GET" && parsed.pathname === "/v2/positions" && noQuery) return { scope: "positions:read", effect: "read" };
  if (method === "POST" && parsed.pathname === "/v2/orders" && noQuery) return { scope: "orders:live", effect: "place" };
  if (method === "DELETE" && /^\/v2\/orders\/[^/]+$/u.test(parsed.pathname) && noQuery) return { scope: "orders:live", effect: "cancel", orderId: decodeURIComponent(parsed.pathname.slice("/v2/orders/".length)) };
  if (method === "GET" && parsed.pathname === "/v2/orders:by_client_order_id" && query.length === 1 && query[0][0] === "client_order_id" && query[0][1].length > 0 && query[0][1].length <= 128) return { scope: "orders:read", effect: "read" };
  if (method === "GET" && parsed.pathname === "/v2/account/activities" && query.length === 1 && query[0][0] === "activity_types" && query[0][1].length > 0) return { scope: "activities:read", effect: "read" };
  throw new TypeError("live-trading-operation-refused");
}
const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
const paperClientOrderId = (contractId, intentId) => `paper-${createHash("sha256").update(`${contractId}:${intentId}`).digest("hex").slice(0, 48)}`;
const liveClientOrderId = (contractId, intentId) => `live-${createHash("sha256").update(`${contractId}:${intentId}`).digest("hex").slice(0, 48)}`;
function validatePaperOrderAuthorization({ authorization, reference, currentGrant, operation, body, nowMs }) {
  const { contract, authorityGrant, intent, revocation } = authorization ?? {};
  if (typeof reference !== "string" || reference.trim() === "" || intent?.id !== reference || intent.type !== "AggressiveBrokerageOrderIntent") throw new TypeError("exact-paper-order-authorization-required");
  if (contract?.type !== "PrincipalBrokerageServiceContract" || authorityGrant?.type !== "RevocableBrokerageAuthorityGrant" || contract.id !== intent.contract || authorityGrant.id !== currentGrant.id || authorityGrant.principalContract !== contract.id || authorityGrant.revoked !== false || revocation?.effective === true) throw new TypeError("paper-order-authorization-binding-refused");
  if (["credentialReference", "principal", "accountReference", "venue", "adapter", "validUntil"].some((field) => authorityGrant[field] !== currentGrant[field]) || canonical(authorityGrant.scopes) !== canonical(currentGrant.scopes)) throw new TypeError("paper-order-authoritative-grant-drift-refused");
  if (contract.venue !== "alpaca-trading-paper" || authorityGrant.venue !== "alpaca-trading-paper" || authorityGrant.adapter !== "alpaca-trading-paper" || contract.principal !== authorityGrant.principal || contract.accountReference !== authorityGrant.accountReference || !contract.scopes?.includes(operation.scope) || !authorityGrant.scopes?.includes(operation.scope)) throw new TypeError("paper-order-authorization-binding-refused");
  const contractExpiry = instant(contract.validUntil, "paper-contract-expiry"), grantExpiry = instant(authorityGrant.validUntil, "paper-authority-expiry");
  if (nowMs >= contractExpiry || nowMs >= grantExpiry) throw new TypeError("paper-order-authorization-expired");
  if (![intent.notional, intent.maximumLoss, contract.risk?.maximumOrderNotional, contract.risk?.maximumLossAmount].every(Number.isFinite) || intent.notional > contract.risk.maximumOrderNotional || intent.maximumLoss > contract.risk.maximumLossAmount) throw new TypeError("paper-order-risk-limit-refused");
  const allowed = { symbol: intent.symbol, side: intent.side, notional: intent.notional, type: "market", time_in_force: "day", client_order_id: paperClientOrderId(contract.id, intent.id) };
  if (canonical(body) !== canonical(allowed)) throw new TypeError("paper-order-body-drift-refused");
}
function validatePaperCancellationAuthorization({ authorization, reference, currentGrant, operation, nowMs }) {
  if (typeof reference !== "string" || reference.trim() === "" || authorization?.id !== reference || authorization.type !== "PaperOrderCancellationAuthorization" || authorization.authorityGrant !== currentGrant.id || authorization.orderId !== operation.orderId || authorization.revoked !== false) throw new TypeError("exact-paper-cancellation-authorization-required");
  if (nowMs >= instant(authorization.validUntil, "paper-cancellation-expiry")) throw new TypeError("paper-cancellation-authorization-expired");
}
function validateLiveOrderAuthorization({ authorization, reference, currentGrant, operation, body, nowMs }) {
  const { contract, authorityGrant, intent, revocation } = authorization ?? {};
  if (typeof reference !== "string" || reference.trim() === "" || intent?.id !== reference || intent.type !== "AggressiveBrokerageOrderIntent") throw new TypeError("exact-live-order-authorization-required");
  if (contract?.type !== "PrincipalBrokerageServiceContract" || authorityGrant?.type !== "RevocableBrokerageAuthorityGrant" || contract.id !== intent.contract || authorityGrant.id !== currentGrant.id || authorityGrant.principalContract !== contract.id || authorityGrant.revoked !== false || revocation?.effective === true) throw new TypeError("live-order-authorization-binding-refused");
  if (["credentialReference", "principal", "accountReference", "venue", "adapter", "validUntil"].some((field) => authorityGrant[field] !== currentGrant[field]) || canonical(authorityGrant.scopes) !== canonical(currentGrant.scopes)) throw new TypeError("live-order-authoritative-grant-drift-refused");
  if (contract.venue !== "alpaca-trading-live" || authorityGrant.venue !== "alpaca-trading-live" || authorityGrant.adapter !== "alpaca-trading-live" || contract.principal !== authorityGrant.principal || contract.accountReference !== authorityGrant.accountReference || !contract.scopes?.includes(operation.scope) || !authorityGrant.scopes?.includes(operation.scope)) throw new TypeError("live-order-authorization-binding-refused");
  const contractExpiry = instant(contract.validUntil, "live-contract-expiry"), grantExpiry = instant(authorityGrant.validUntil, "live-authority-expiry");
  if (nowMs >= contractExpiry || nowMs >= grantExpiry) throw new TypeError("live-order-authorization-expired");
  if (![intent.notional, intent.maximumLoss, contract.risk?.maximumOrderNotional, contract.risk?.maximumLossAmount].every(Number.isFinite) || intent.notional > contract.risk.maximumOrderNotional || intent.maximumLoss > contract.risk.maximumLossAmount) throw new TypeError("live-order-risk-limit-refused");
  const allowed = { symbol: intent.symbol, side: intent.side, notional: intent.notional, type: "market", time_in_force: "day", client_order_id: liveClientOrderId(contract.id, intent.id) };
  if (canonical(body) !== canonical(allowed)) throw new TypeError("live-order-body-drift-refused");
}
function validateLiveCancellationAuthorization({ authorization, reference, currentGrant, operation, nowMs }) {
  if (typeof reference !== "string" || reference.trim() === "" || authorization?.id !== reference || authorization.type !== "LiveOrderCancellationAuthorization" || authorization.authorityGrant !== currentGrant.id || authorization.orderId !== operation.orderId || authorization.revoked !== false) throw new TypeError("exact-live-cancellation-authorization-required");
  if (nowMs >= instant(authorization.validUntil, "live-cancellation-expiry")) throw new TypeError("live-cancellation-authorization-expired");
}

export function createBrokerageAuthorityCustody({ authorityCustody, transport, resolveAuthorityGrant, resolvePaperOperationAuthorization, resolvePaperObservationAuthorization, resolveLiveOperationAuthorization, fetchImpl = fetch, brokerTokenEndpoint = "https://authx.alpaca.markets/v1/oauth2/token", clock = () => new Date().toISOString() }) {
  if (typeof transport !== "function") throw new TypeError("custody-owned-transport-required");
  if (!["store", "retrieve", "revoke"].every((method) => typeof authorityCustody?.[method] === "function")) throw new TypeError("authority-custody-actuator-required");
  return Object.freeze({
    async authorizedRequest({ credentialReference, authorityGrantReference, observationAuthorizationReference, operationAuthorizationReference, product, scope, method, url, body }) {
      let record, effectiveScope = scope;
      if (!PRODUCT_KINDS[product]) throw new TypeError("unknown-brokerage-product-refused");
      const requestTime = clock(), requestTimeMs = instant(requestTime, "custody-clock");
      if (product === "alpaca-trading-paper") {
        const operation = paperOperation(method, paperOrigin(url));
        if (typeof observationAuthorizationReference === "string") {
          if (typeof resolvePaperObservationAuthorization !== "function" || authorityGrantReference !== undefined || operationAuthorizationReference !== undefined || credentialReference !== undefined || scope !== undefined || operation.effect !== "read" || !["account:read", "positions:read"].includes(operation.scope)) throw new TypeError("paper-observation-authorization-refused");
          const authorization = await resolvePaperObservationAuthorization(observationAuthorizationReference);
          if (authorization?.id !== observationAuthorizationReference || authorization.type !== "PrincipalPaperAccountObservationAuthorization" || authorization.revoked !== false || authorization.venue !== "alpaca-trading-paper" || !authorization.scopes?.includes(operation.scope) || requestTimeMs >= instant(authorization.validUntil, "paper-observation-expiry")) throw new TypeError("current-paper-observation-authorization-required");
          record = await authorityCustody.retrieve(authorization.credentialReference);
          if (!record || record.kind !== "alpaca-trading-api-key" || record.environment !== "paper" || record.venue !== "alpaca-trading-paper" || record.accountReference !== authorization.accountAlias) throw new TypeError("paper-observation-credential-binding-refused");
          effectiveScope = operation.scope; credentialReference = authorization.credentialReference;
        } else {
        if (typeof resolveAuthorityGrant !== "function") throw new TypeError("paper-authority-grant-resolver-required");
        if (credentialReference !== undefined || scope !== undefined || typeof authorityGrantReference !== "string" || authorityGrantReference.trim() === "") throw new TypeError("paper-authority-reference-only-required");
        const grant = await resolveAuthorityGrant(authorityGrantReference);
        if (grant?.id !== authorityGrantReference || grant.type !== "RevocableBrokerageAuthorityGrant" || grant.revoked !== false) throw new TypeError("current-paper-authority-grant-required");
        const grantExpiry = instant(grant.validUntil, "paper-authority-expiry");
        if (requestTimeMs >= grantExpiry) throw new TypeError("paper-authority-expired");
        record = await authorityCustody.retrieve(grant.credentialReference);
        if (!record) throw new TypeError("credential-reference-revoked-or-unknown");
        if (record.kind !== "alpaca-trading-api-key" || record.environment !== "paper" || record.venue !== "alpaca-trading-paper" || grant.principal !== record.principal || grant.accountReference !== record.accountReference || grant.venue !== record.venue || grant.adapter !== "alpaca-trading-paper") throw new TypeError("paper-authority-binding-mismatch");
        effectiveScope = operation.scope;
        if (!grant.scopes?.includes(effectiveScope)) throw new TypeError("paper-authority-operation-scope-refused");
        if (operation.effect !== "read") {
          if (typeof resolvePaperOperationAuthorization !== "function") throw new TypeError("paper-operation-authorization-resolver-required");
          if (typeof operationAuthorizationReference !== "string" || operationAuthorizationReference.trim() === "") throw new TypeError("exact-paper-operation-authorization-required");
          const authorization = await resolvePaperOperationAuthorization(operationAuthorizationReference);
          if (operation.effect === "place") validatePaperOrderAuthorization({ authorization, reference: operationAuthorizationReference, currentGrant: grant, operation, body, nowMs: requestTimeMs });
          else validatePaperCancellationAuthorization({ authorization, reference: operationAuthorizationReference, currentGrant: grant, operation, nowMs: requestTimeMs });
        } else if (operationAuthorizationReference !== undefined) throw new TypeError("paper-read-operation-authorization-refused");
        credentialReference = grant.credentialReference;
        }
      } else if (product === "alpaca-trading-live") {
        const operation = liveOperation(method, liveOrigin(url));
        if (observationAuthorizationReference !== undefined) throw new TypeError("live-observation-shortcut-not-supported");
        if (typeof resolveAuthorityGrant !== "function") throw new TypeError("live-authority-grant-resolver-required");
        if (credentialReference !== undefined || scope !== undefined || typeof authorityGrantReference !== "string" || authorityGrantReference.trim() === "") throw new TypeError("live-authority-reference-only-required");
        const grant = await resolveAuthorityGrant(authorityGrantReference);
        if (grant?.id !== authorityGrantReference || grant.type !== "RevocableBrokerageAuthorityGrant" || grant.revoked !== false) throw new TypeError("current-live-authority-grant-required");
        const grantExpiry = instant(grant.validUntil, "live-authority-expiry");
        if (requestTimeMs >= grantExpiry) throw new TypeError("live-authority-expired");
        record = await authorityCustody.retrieve(grant.credentialReference);
        if (!record) throw new TypeError("credential-reference-revoked-or-unknown");
        if (record.kind !== "alpaca-trading-api-key-live" || record.environment !== "live" || record.venue !== "alpaca-trading-live" || grant.principal !== record.principal || grant.accountReference !== record.accountReference || grant.venue !== record.venue || grant.adapter !== "alpaca-trading-live") throw new TypeError("live-authority-binding-mismatch");
        effectiveScope = operation.scope;
        if (!grant.scopes?.includes(effectiveScope)) throw new TypeError("live-authority-operation-scope-refused");
        if (operation.effect !== "read") {
          if (typeof resolveLiveOperationAuthorization !== "function") throw new TypeError("live-operation-authorization-resolver-required");
          if (typeof operationAuthorizationReference !== "string" || operationAuthorizationReference.trim() === "") throw new TypeError("exact-live-operation-authorization-required");
          const authorization = await resolveLiveOperationAuthorization(operationAuthorizationReference);
          if (operation.effect === "place") validateLiveOrderAuthorization({ authorization, reference: operationAuthorizationReference, currentGrant: grant, operation, body, nowMs: requestTimeMs });
          else validateLiveCancellationAuthorization({ authorization, reference: operationAuthorizationReference, currentGrant: grant, operation, nowMs: requestTimeMs });
        } else if (operationAuthorizationReference !== undefined) throw new TypeError("live-read-operation-authorization-refused");
        credentialReference = grant.credentialReference;
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
