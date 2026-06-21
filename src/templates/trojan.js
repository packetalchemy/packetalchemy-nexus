export function generateTrojanTemplate(
  host,
  country
) {
  return `trojan://password@${host}:443#${country}`;
}