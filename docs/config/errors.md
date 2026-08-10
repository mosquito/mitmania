# Error pages and status codes

mitmania-generated HTTP responses use a Squid-style page and a stable `ERR_*` class.

| Situation | Status | Error class |
| --- | ---: | --- |
| no rule match | 511 | `ERR_ACCESS_DENIED` |
| proxy auth required/failed | 407 | `ERR_CACHE_ACCESS_DENIED` |
| egress/self-guard denied | 403 | `ERR_FORWARDING_DENIED` |
| rule `raise` | 403 by default | `ERR_ACCESS_DENIED` |
| broker denied | 403 or configured status | `ERR_OUTCALL_DENIED` |
| malformed request | 400 | `ERR_INVALID_REQ` |
| headers/URI too large | 431 / 414 | `ERR_TOO_BIG` |
| upstream DNS/unreachable | 523 | `ERR_DNS_FAIL` |
| upstream refused | 521 | `ERR_CONNECT_FAIL` |
| connect/read timeout | 522 / 524 | `ERR_CONNECT_FAIL` / `ERR_READ_TIMEOUT` |
| upstream TLS failure | 525 | `ERR_SECURE_CONNECT_FAIL` |
| bad gateway response | 502 | `ERR_INVALID_RESP` |
| forwarding loop | 508 | `ERR_ACCESS_DENIED` |
| internal failure | 500 | `ERR_GATEWAY_FAILURE` |

Before an explicit tunnel, the status is the `CONNECT` response. After TLS starts, mitmania may need a fallback leaf to deliver the page over TLS; otherwise it resets. Plain HTTP receives the response directly.

