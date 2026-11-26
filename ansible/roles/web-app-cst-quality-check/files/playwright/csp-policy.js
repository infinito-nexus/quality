const SCRIPT_DIRECTIVES = ["script-src", "script-src-elem", "script-src-attr"];

function originOf(token) {
  try {
    return new URL(token).origin;
  } catch {
    return "";
  }
}

function sourcesBeyond(directives, directive, origins) {
  const tokens = directives[directive] || [];
  const beyond = tokens.filter((token) => token !== "'self'" && !origins.includes(originOf(token)));
  return (tokens.includes("'self'") ? beyond : ["missing 'self'", ...beyond]).map((token) => `${directive} ${token}`);
}

/**
 * Args:
 *   directives: the parsed Content-Security-Policy response header, as parseCspHeader of the shared personas returns it.
 *   cdnOrigin: origin of core's CDN, which build_csp_header adds to the script directives of every role.
 *
 * Returns:
 *   One "<directive> <source>" entry per worker source other than 'self' and per script source other than 'self'
 *   and cdnOrigin, keywords such as 'unsafe-inline' included; empty for a policy that runs scripts and workers from 'self' only.
 */
function openScriptSources(directives, cdnOrigin) {
  return [
    ...sourcesBeyond(directives, "worker-src", []),
    ...SCRIPT_DIRECTIVES.flatMap((directive) => sourcesBeyond(directives, directive, [cdnOrigin])),
  ];
}

module.exports = { openScriptSources };
