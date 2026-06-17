export function createContext(request, env) {
  return {
    request,
    env,
    url: new URL(request.url),
    timestamp: Date.now()
  };
}
