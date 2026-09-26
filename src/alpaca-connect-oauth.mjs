const DEFAULT_AUTHORIZE = "https://app.alpaca.markets/oauth/authorize";
const DEFAULT_TOKEN = "https://api.alpaca.markets/oauth/token";
const ALLOWED_ENVIRONMENTS = new Set(["paper", "live"]);
const accountEndpointFor = (environment) => `${environment === "live" ? "https://api.alpaca.markets" : "https://paper-api.alpaca.markets"}/v2/account`;

export function createAlpacaConnectOAuthBroker({ clientId, clientSecret, redirectUri, custody, fetchImpl = fetch,
  authorizeEndpoint = DEFAULT_AUTHORIZE, tokenEndpoint = DEFAULT_TOKEN, allowedScopes = ["account:write", "trading"] }) {
  if (!clientId || !clientSecret || !redirectUri || typeof custody?.store !== "function") throw new TypeError("alpaca-connect-oauth-configuration-incomplete");
  const allowed = new Set(allowedScopes);
  return Object.freeze({
    authorizationUrl({ state, environment = "paper", scopes = [] }) {
      if (typeof state !== "string" || state.length < 32 || !ALLOWED_ENVIRONMENTS.has(environment) || scopes.some((scope) => !allowed.has(scope))) throw new TypeError("oauth-state-environment-or-scope-refused");
      const url = new URL(authorizeEndpoint); url.search = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, state, env: environment, ...(scopes.length ? { scope: scopes.join(" ") } : {}) }).toString(); return url.toString();
    },
    async exchangeAuthorizationCode({ code, state, expectedState, principal, environment = "paper" }) {
      if (!code || !state || state !== expectedState || !ALLOWED_ENVIRONMENTS.has(environment)) throw new TypeError("oauth-state-environment-or-code-refused");
      const response = await fetchImpl(tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri }) });
      if (!response?.ok) throw new TypeError("alpaca-oauth-code-exchange-refused"); const token = await response.json(); if (!token?.access_token) throw new TypeError("alpaca-oauth-token-response-invalid");
      const accountResponse = await fetchImpl(accountEndpointFor(environment), { headers: { Authorization: `Bearer ${token.access_token}` } });
      if (!accountResponse?.ok) throw new TypeError("alpaca-oauth-selected-account-read-refused");
      const account = await accountResponse.json();
      const accountReference = typeof account?.account_number === "string" && account.account_number.trim()
        ? account.account_number.trim()
        : typeof account?.id === "string" && account.id.trim() ? account.id.trim() : null;
      if (!accountReference) throw new TypeError("alpaca-oauth-selected-account-reference-required");
      const expiresAt = Number.isFinite(Number(token.expires_in)) ? new Date(Date.now() + Number(token.expires_in) * 1000).toISOString() : undefined;
      const venue = `alpaca-trading-${environment}`;
      return custody.store({ provider: "alpaca", subject: principal, attributes: { kind: "alpaca-oauth", environment, venue, accountReference, expiresAt: expiresAt ?? null }, secret: { kind: "alpaca-oauth", principal, environment, venue, accountReference, credential: { accessToken: token.access_token, refreshToken: token.refresh_token, ...(expiresAt ? { expiresAt } : {}) } } });
    },
  });
}
