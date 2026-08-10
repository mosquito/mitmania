# Block, rewrite, and redact

**Who and why:** rule authors reject sensitive operations, normalize headers, or replace a bounded body prefix.

**MITM required?** HTTPS message matching and mutation require interception; plaintext HTTP does not.

Use request-side `raise`/`block`, `header.add`, and `header.set`; response-side actions also include `body.replace` and `status.set`. `raise` produces a Squid-style page, while `block` closes the connection. Body work is limited to `--http-body-window`; bytes beyond the window stream untouched.

Review [Matching and actions](../config/actions.md) and [Error pages](../config/errors.md).

