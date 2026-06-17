import { routeRequest } from "./router";
import { securityCheck } from "./security";
import { createContext } from "./context";

export async function handleRequest(request, env, ctx) {
  const context = createContext(request, env);

  // 1. Security Layer
  const secure = securityCheck(context);
  if (!secure.ok) {
    return new Response("Blocked", { status: 403 });
  }

  // 2. Routing Layer
  const target = routeRequest(context);

  // 3. Protocol Handler (future-ready)
  if (target.type === "vless") {
    return new Response("VLESS not implemented", { status: 501 });
  }

  if (target.type === "trojan") {
    return new Response("Trojan not implemented", { status: 501 });
  }

  // default
  return new Response("Nexus Edge Running", {
    status: 200
  });
}
