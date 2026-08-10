# Bring your own CA

BYO-CA imports an organizational signing CA into the encrypted `ca.p12` Storage object so already-trusting clients need no additional root installation. The accepted recipes and exact import commands depend on the CA's existing key and chain format.

!!! danger "Security"
    This operation can expand interception authority from a dedicated proxy root to an organizational trust anchor. Use a constrained intermediate where possible, document the path length and name constraints, and test in isolated Storage before replacing fleet state.

The OpenSSL conversion recipes still need executable fixtures before they can be published as a copy-runnable tutorial. For current deployments, use the generated dedicated CA and follow [CA operations](../ops/ca.md).

