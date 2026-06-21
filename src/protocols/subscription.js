import { selectRoute } from "../policies/routing";
import { generateVlessTemplate } from "../templates/vless";
import { generateTrojanTemplate } from "../templates/trojan";

export async function handleSubscription(request) {

  const url = new URL(request.url);

  const type =
    url.searchParams.get("type") || "vless";

  const country =
    url.searchParams.get("country") || "AUTO";

  const host = url.host;

  const route =
    selectRoute(country);

  const options = {
    uuid:
      url.searchParams.get("uuid"),

    path:
      url.searchParams.get("path"),

    tls:
      url.searchParams.get("tls") !== "false"
  };

  let config;

  if (type === "vless") {

    config =
      generateVlessTemplate(
        host,
        country,
        options
      );

  } else if (type === "trojan") {

    config =
      generateTrojanTemplate(
        host,
        country
      );

  } else {

    config =
      "unsupported protocol";

  }

  return Response.json({
    protocol: type,
    country,
    route,
    config,
    status: "generated"
  });
}