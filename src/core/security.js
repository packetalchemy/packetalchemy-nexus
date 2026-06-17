export function securityCheck(context) {
  const ip = context.request.headers.get("CF-Connecting-IP");

  // خیلی ساده فعلاً
  if (!ip) {
    return { ok: false };
  }

  return { ok: true };
}
