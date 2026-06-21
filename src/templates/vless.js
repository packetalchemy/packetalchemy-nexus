export function generateVlessTemplate(
  host,
  country,
  options = {}
) {
  const uuid =
    options.uuid ||
    "00000000-0000-0000-0000-000000000000";

  const path =
    options.path || "/";

  const security =
    options.tls === false
      ? "none"
      : "tls";

  return `vless://${uuid}@${host}:443?type=ws&security=${security}&path=${encodeURIComponent(path)}#${country}`;
}