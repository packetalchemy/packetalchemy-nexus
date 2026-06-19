export function routeRequest(request) {
  const url = new URL(request.url);

  if (url.pathname.startsWith("/vless")) {
    return "vless";
  }

  if (url.pathname.startsWith("/trojan")) {
    return "trojan";
  }

  if (url.pathname === "/health") {
    return "health";
  }

  return "default";
}
