# Worker Request Flow

```text
Request
  ↓
Cloudflare Edge
  ↓
Worker Logic
  ↓
Origin Response
```

Workers can:
- Inspect requests
- Modify headers
- Apply policies
- Route traffic
```
