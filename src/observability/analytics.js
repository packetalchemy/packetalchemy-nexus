import { incrementRequests } from "./metrics";
import { log } from "./logger";

export function track(event, data = {}) {
  if (event === "request") {
    incrementRequests();
  }

  log("info", event, data);
}