import { incrementRequests } from "./metrics";

export function track(event, data = {}) {
  if (event === "request") {
    incrementRequests();
  }

  console.log(
    JSON.stringify({
      event,
      timestamp: Date.now(),
      ...data
    })
  );
}