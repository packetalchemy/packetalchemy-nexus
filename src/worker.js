export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        project: "PacketAlchemy Nexus",
        version: "0.1.0-alpha",
        timestamp: new Date().toISOString()
      });
    }

    return new Response("PacketAlchemy Nexus", {
      status: 200
    });
  }
};
