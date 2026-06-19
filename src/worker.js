import { routeRequest } from "./routing/router";
import { dispatchProtocol } from "./protocols";
import { track } from "./observability/analytics";
import { config } from "./config/config";
import { getMetrics } from "./observability/metrics";

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
        service: config.project,
        version: config.version,
        protocols: config.protocols,
        metrics: getMetrics()
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
