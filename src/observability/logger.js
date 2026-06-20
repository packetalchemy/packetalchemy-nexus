export function log(level, message, data = {}) {
    console.log(
      JSON.stringify({
        level,
        message,
        timestamp: new Date().toISOString(),
        ...data
      })
    );
  }