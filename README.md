# actions-oidc-gateway-slickdeals

[![Run CI](https://github.com/Slickdeals/actions-oidc-gateway-slickdeals/actions/workflows/ci.yml/badge.svg)](https://github.com/Slickdeals/actions-oidc-gateway-slickdeals/actions/workflows/ci.yml)

An OIDC gateway that authorizes traffic from GitHub Actions into your private network, either as an API gateway or as an HTTP CONNECT proxy tunnel.

## Authorization

The gateway validates GitHub Actions OIDC tokens and enforces the following claims:

- **`repository_owner`** must equal `Slickdeals` -- only workflows running in the Slickdeals GitHub Organization are permitted.
- **`aud`** must equal `api://ActionsOIDCGateway` -- prevents token reuse across services.

### Repo allowlist

By default, only the `sd-core` repository is authorized to use the OIDC gateway. To modify the allowlist, update the `allowedRepos` variable in `oidc_gateway.go`:

```go
var allowedRepos = []string{"sd-core", "other-repo"}
```

When `allowedRepos` is non-empty, only the listed repositories (by name, not `org/repo`) are permitted. Set it to an empty slice to allow all repos in the org.

For other claims you can check, see [Configuring the OIDC trust with the cloud](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-oidc-trust-with-the-cloud).

## API Gateway

The gateway proxies API requests to the `sd-core` service. All requests to paths starting with `/api/` are forwarded to `http://sd-core.internal:8080`.

For example, a request to `https://your-load-balancer.example.com/api/v1/users` will be proxied to `http://sd-core.internal:8080/api/v1/users`.

## Customization

If you need to modify the target service URL or add additional routing logic, update the `handleApiRequest` function in `oidc_gateway.go`.

Lastly, you are responsible for deploying this gateway in a secure way with access to your private network. There's lots of different options here, but you probably want this gateway to be behind a load balancer that speaks TLS, with scoped network access to the private services it provides access to. That will probably look something like this:

```mermaid
flowchart LR
    Runner-->|Actions OIDC Token| LB
    subgraph GitHub Actions
    Runner[Runner]
    end
    subgraph Private Network
    LB[Load Balancer]
    LB-->G1[This Gateway]
    LB-->G2[This Gateway]
    G1-->PS[sd-core]
    end
```

## How would I use this?

Once you customize and deploy your gateway, you can configure your Actions workflow to make use of it:

```yaml
...

jobs:
  your_job_name:
    ...
    permissions:
      id-token: write
    steps:
      ...

      - name: Get OIDC token and set OIDC_TOKEN environment variable
        run: |
          echo "OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" -H "Accept: application/json; api-version=2.0" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://ActionsOIDCGateway" | jq -r ".value")"  >> $GITHUB_ENV
          echo "::add-mask::$OIDC_TOKEN"

      - name: Example of using gateway as a proxy
        run: |
          curl -v -p --proxy-header "Gateway-Authorization: ${{ env.OIDC_TOKEN }}" -x https://your-load-balancer.example.com https://www.google.com

      - name: Example of an API gateway call to sd-core
        run: |
          curl -v -H "Gateway-Authorization: ${{ env.OIDC_TOKEN }}" https://your-load-balancer.example.com/api/v1/endpoint

    ...
```
