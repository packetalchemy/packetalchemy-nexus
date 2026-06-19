const metrics = {
    requests: 0,
    errors: 0,
    startedAt: Date.now()
  };
  
  export function incrementRequests() {
    metrics.requests++;
  }
  
  export function incrementErrors() {
    metrics.errors++;
  }
  
  export function getMetrics() {
    return {
      ...metrics,
      uptime: Math.floor(
        (Date.now() - metrics.startedAt) / 1000
      )
    };
  }