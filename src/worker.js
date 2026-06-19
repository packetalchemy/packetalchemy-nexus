import { routeRequest } from "./routing/router";
import { dispatchProtocol } from "./protocols";
import { track } from "./analytics/analytics";

export default {
  async fetch(request) {
    const start = Date.now();

    const route = routeRequest(request);

    track("request", {
      route
    });

    if (route === "health") {
      return Response.json({
        status: "ok",
        service: "PacketAlchemy Nexus",
        version: "0.2.0-dev"
      });
    }

    const protocolResponse =
      await dispatchProtocol(route, request);

    if (protocolResponse) {
      return protocolResponse;
    }

    track("latency", {
      ms: Date.now() - start
    });

    return new Response("Nexus Edge Online");
  }
};
