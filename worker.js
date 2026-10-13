/**
 * sentinel — Worker + Static Assets con security headers.
 * Inyecta headers en todas las respuestas (paridad con Portafolio).
 */

const SEC_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "X-Permitted-Cross-Domain-Policies": "none",
};
const CSP =
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; font-src 'self'; connect-src 'self'; " +
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

const GOOGLE_FILE = "/google0cbe515c88088343.html";
const GOOGLE_BODY = "google-site-verification: google0cbe515c88088343.html";

async function secAssets(request, env) {
    const res = await env.ASSETS.fetch(request);
    const h = new Headers(res.headers);
    for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
    if ((h.get("Content-Type") || "").includes("text/html")) {
        h.set("Content-Security-Policy", CSP);
    }
    return new Response(res.body, { status: res.status, headers: h });
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        if (url.pathname === GOOGLE_FILE) {
            return new Response(GOOGLE_BODY, {
                headers: {
                    "Content-Type": "text/html; charset=utf-8",
                    ...SEC_HEADERS,
                    "Content-Security-Policy": CSP,
                },
            });
        }
        return secAssets(request, env);
    },
};
