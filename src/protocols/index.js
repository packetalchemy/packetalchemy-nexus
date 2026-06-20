import { handleVless } from "./vless";
import { handleTrojan } from "./trojan";
import { handleSubscription } from "./subscription";

export async function dispatchProtocol(type, request) {
  switch (type) {
    case "vless":
      return handleVless(request);

    case "trojan":
      return handleTrojan(request);

    case "subscription":
      return handleSubscription(request);

    default:
      return null;
  }
}
