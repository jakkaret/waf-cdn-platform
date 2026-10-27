// Gen 3 inline gate (2026-10-27): `js_content mlgate.gate;` in the main
// `location /` of the tunnel server (default.conf.template) and of every
// direct-mode site (services/nginx_site_service.py). It runs after
// ModSecurity and the shield, so it only sees requests both let through.
//
// $ml_gate comes from the map services/ml_gate.py renders. Empty -- every host
// whose origin is in log mode, and any host the map does not list -- means
// the request goes straight to @waf_origin with no ML call: the same path as
// before this gate existed. Otherwise ("enforce:<challenge>:<block>"):
//
//   1. the body (as ModSecurity already read it) goes to /internal-ml-gate,
//      which answers the action on X-WAF-ML-Action;
//   2. "block"      -> 403 (the static /403.html, like a ModSecurity block);
//   3. "challenge"  -> pass if /internal-ml-clearance says the visitor holds a
//                      CAPTCHA clearance, else 401 with $shield_type "ml", which
//                      the server's `error_page 401` turns into the challenge page;
//   4. anything else, or any error or timeout -> pass (fail open).
//
// A clearance only ever lifts the challenge band: "block" never asks for it.

const MAX_BODY = 65536;

function bodyText(r) {
    try {
        // undefined when nginx spooled the body to a file (over 64k):
        // that request is scored without its body.
        const text = r.requestText;
        if (!text) {
            return '';
        }
        return text.length > MAX_BODY ? text.slice(0, MAX_BODY) : text;
    } catch (e) {
        return '';
    }
}

async function decide(r) {
    try {
        const res = await r.subrequest('/internal-ml-gate', { method: 'POST', body: bodyText(r) });
        const action = res.headersOut['X-WAF-ML-Action'] || 'pass';
        if (action === 'block') {
            return 'block';
        }
        if (action !== 'challenge') {
            return 'pass';
        }
        const clearance = await r.subrequest('/internal-ml-clearance', { method: 'GET' });
        return clearance.status === 204 ? 'pass' : 'challenge';
    } catch (e) {
        r.warn('ml gate failed open: ' + e);
        return 'pass';
    }
}

async function gate(r) {
    // decide() never throws.
    const action = r.variables.ml_gate ? await decide(r) : 'pass';
    if (action === 'block') {
        r.return(403);
        return;
    }
    if (action === 'challenge') {
        try {
            r.variables.shield_type = 'ml';
        } catch (e) {
            r.warn('ml gate failed open, no challenge type: ' + e);
            r.internalRedirect('@waf_origin');
            return;
        }
        r.return(401);
        return;
    }
    r.internalRedirect('@waf_origin');
}

export default { gate };
