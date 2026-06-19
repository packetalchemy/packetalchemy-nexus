export async function handleVless() {
  return new Response(
    JSON.stringify({
      protocol: "vless",
      status: "not implemented"
    }),
    {
      headers: {
        "content-type": "application/json"
      }
    }
  );
}
