/**
 * Cloudflare Pages Function — API Proxy
 * Forwards all /api/* requests to the haru-stream Worker.
 *
 * IMPORTANT: Replace WORKER_URL with your actual Worker URL.
 * Format: https://haru-stream.<your-subdomain>.workers.dev
 */

const WORKER_URL = 'https://haru-stream.YOUR_SUBDOMAIN.workers.dev';

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  // Build the target URL pointing to the Worker
  const targetUrl = WORKER_URL + url.pathname + url.search;

  // Clone the request with the new URL
  const newRequest = new Request(targetUrl, {
    method:  request.method,
    headers: request.headers,
    body:    ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
    redirect: 'follow',
  });

  const response = await fetch(newRequest);

  // Return the Worker's response as-is
  return new Response(response.body, {
    status:  response.status,
    headers: response.headers,
  });
}
