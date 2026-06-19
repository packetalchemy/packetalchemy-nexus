export async function handleTrojan() {
  return new Response(
    JSON.stringify({
      protocol: "trojan",
      status: "not implemented"
    }),
    {
      headers: {
        "content-type": "application/json"
      }
    }
  );
}
