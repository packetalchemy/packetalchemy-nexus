import { selectRoute } from "../policies/routing";

export async function handleSubscription(request) {

  const url = new URL(request.url);

  const type =
    url.searchParams.get("type") || "vless";

  const country =
    url.searchParams.get("country") || "AUTO";

  const route =
    selectRoute(country);

  return Response.json({
    protocol: type,
    country,
    route,
    status: "generated"
  });
}