"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.assertConfig = assertConfig;

var _errors = require("../errors");

let warned = false;

function isValidHttpUrl(url, baseUrl) {
  try {
    return /^https?:/.test(new URL(url, url.startsWith("/") ? baseUrl : undefined).protocol);
  } catch (_unused) {
    return false;
  }
}

function assertConfig(params) {
  var _req$query;

  const {
    options,
    req
  } = params;
  const warnings = [];

  if (!warned) {
    if (!req.origin) warnings.push("NEXTAUTH_URL");
    if (!options.secret && process.env.NODE_ENV !== "production") warnings.push("NO_SECRET");
    if (options.debug) warnings.push("DEBUG_ENABLED");
  }

  if (!options.secret && process.env.NODE_ENV === "production") {
    return new _errors.MissingSecret("Please define a `secret` in production.");
  }

  if (!((_req$query = req.query) !== null && _req$query !== void 0 && _req$query.nextauth) && !req.action) {
    return new _errors.MissingAPIRoute("Cannot find [...nextauth].{js,ts} in `/pages/api/auth`. Make sure the filename is written correctly.");
  }

  let hasCredentials, hasEmail;
  let hasTwitterOAuth2;

  for (const provider of options.providers) {
    if (provider.type === "credentials") hasCredentials = true;else if (provider.type === "email") hasEmail = true;else if (provider.id === "twitter" && provider.version === "2.0") hasTwitterOAuth2 = true;
  }

  if (hasCredentials) {
    var _options$session;

    const dbStrategy = ((_options$session = options.session) === null || _options$session === void 0 ? void 0 : _options$session.strategy) === "database";
    const onlyCredentials = !options.providers.some(p => p.type !== "credentials");

    if (dbStrategy && onlyCredentials) {
      return new _errors.UnsupportedStrategy("Signin in with credentials only supported if JWT strategy is enabled");
    }

    const credentialsNoAuthorize = options.providers.some(p => p.type === "credentials" && !p.authorize);

    if (credentialsNoAuthorize) {
      return new _errors.MissingAuthorize("Must define an authorize() handler to use credentials authentication provider");
    }
  }

  if (hasEmail) {
    const {
      adapter
    } = options;

    if (!adapter) {
      return new _errors.MissingAdapter("E-mail login requires an adapter.");
    }

    const missingMethods = ["createVerificationToken", "useVerificationToken", "getUserByEmail"].filter(method => !adapter[method]);

    if (missingMethods.length) {
      return new _errors.MissingAdapterMethods(`Required adapter methods were missing: ${missingMethods.join(", ")}`);
    }
  }

  if (!warned) {
    if (hasTwitterOAuth2) warnings.push("TWITTER_OAUTH_2_BETA");
    warned = true;
  }

  return warnings;
}