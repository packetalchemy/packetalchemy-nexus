import { handleVless } from "./vless";
import { handleTrojan } from "./trojan";

export async function dispatchProtocol(type, request) {
  switch (type) {
    case "vless":
      return handleVless(request);

    case "trojan":
      return handleTrojan(request);

    default:
      return null;
  }
}
