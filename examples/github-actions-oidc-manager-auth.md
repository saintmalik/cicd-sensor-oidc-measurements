# Action / workflow wiring expected for Manager OIDC (cicd-sensor-action is a
# separate repo; this documents the contract the Agent project start path now
# accepts).

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # When cicd-sensor-action grows manager-auth: oidc, it should:
      # 1) start the Agent with optional id-token-request-url-hosts (GHES)
      # 2) call project start with:
      #      manager_url: ${{ inputs.manager-url }}
      #      manager_auth: oidc
      #      id_token_request_url: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
      #      id_token_request_token: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}
      #      id_token_audience: <manager origin>   # optional; defaults to manager_url origin
      # 3) keep permissions.id-token: write on the job
      #
      # Equivalent CLI (Agent already running):
      #   cicd-sensor project start \
      #     --manager-url https://manager.example.com \
      #     --manager-auth oidc
      #   # reads ACTIONS_ID_TOKEN_REQUEST_URL / TOKEN from the environment
```
