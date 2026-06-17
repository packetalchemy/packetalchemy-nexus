export function routeRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path.startsWith("/vless")) {
    return { type: "vless" };
  }

  if (path.startsWith("/trojan")) {
    return { type: "trojan" };
  }

  return { type: "default" };
}
