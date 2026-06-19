export function track(event, data = {}) {
  console.log(
    JSON.stringify({
      event,
      timestamp: Date.now(),
      ...data
    })
  );
}
