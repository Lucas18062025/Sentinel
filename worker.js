/**
 * sentinel — Worker mínimo + Static Assets.
 * Solo intercepta la verificación de Google Search Console con URL exacta
 * (200, sin redirect). Todo lo demás cae a los assets con el manejo
 * por defecto (incluido / → index.html).
 */

const GOOGLE_FILE = "/google0cbe515c88088343.html";
const GOOGLE_BODY = "google-site-verification: google0cbe515c88088343.html";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        if (url.pathname === GOOGLE_FILE) {
            return new Response(GOOGLE_BODY, {
                headers: {
                    "Content-Type": "text/html; charset=utf-8",
                    "X-Content-Type-Options": "nosniff",
                },
            });
        }
        return env.ASSETS.fetch(request);
    },
};
