import { getRegion } from "./geo";

export function selectRoute(country = "AUTO") {

  const region = getRegion(country);

  return {
    region,
    strategy: "lowest-latency"
  };
}