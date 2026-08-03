/**
 * Cloudflare Pages Function — API Proxy
 * Forwards all /api/* requests to the haru-stream Worker.
 *
 * IMPORTANT: Replace WORKER_URL with your actual Worker URL.
 * Format: https://haru-stream.<your-subdomain>.workers.dev
 */

const WORKER_URL = 'https://haru-stream.ilhamromadon220907.workers.dev';

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  // If the request is for the API or Auth, proxy it to the Worker
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/auth')) {
    const targetUrl = WORKER_URL + url.pathname + url.search;

    const newRequest = new Request(targetUrl, {
      method:  request.method,
      headers: request.headers,
      body:    ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'follow',
    });

    const response = await fetch(newRequest);
    return new Response(response.body, {
      status:  response.status,
      headers: response.headers,
    });
  }

  // Otherwise, serve the static frontend assets from Cloudflare Pages
  return next();
}
