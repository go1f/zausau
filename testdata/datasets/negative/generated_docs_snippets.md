# Configuration Guide

```env
API_KEY=<YOUR_API_KEY>
TOKEN=${TOKEN}
COOKIE_SECRET=process.env.COOKIE_SECRET
```

```json
{
  "password_policy": "Minimum 12 characters",
  "secret_label": "Shown to workspace admins",
  "phone_example": "138****8000",
  "location_note": "Rounded to city level only"
}
```

```yaml
auth:
  token: "<YOUR_BEARER_TOKEN>"
  session: "${SESSION_ID}"
  cookie: "See browser developer tools"
```
