export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "PacketAlchemy Nexus",
        version: "0.1.0-alpha"
      });
    }

    return new Response("Nexus Edge Online", { status: 200 });
  }
};
