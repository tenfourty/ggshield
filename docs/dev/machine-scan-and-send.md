# Machine Scan-and-Send Feature

## Status: Blocked - Awaiting GitGuardian Team Input

The `ggshield machine scan-and-send` and `ggshield machine ping` commands are implemented but **blocked on understanding the correct NHI inventory payload format**.

## What Works

1. **Scanning**: Local machine scanning works - finds secrets in env vars, .env files, private keys, GitHub tokens
2. **Analysis**: GitGuardian API analysis works - detects secret types, validity, checks HMSL for leaks
3. **API Connectivity**: The `/v1/nhi/ping` and `/v1/nhi/inventory/upload` endpoints accept our requests and return success
4. **Authentication**: `GITGUARDIAN_NHI_API_KEY` environment variable support for service accounts with `nhi:send-inventory` scope

## What's Blocked

**The uploaded inventory doesn't appear in the GitGuardian NHI dashboard.**

The upload returns a success response with `raw_data_id`, but secrets don't show up when searching in the NHI Governance → Inventory UI.

### Root Cause Investigation

We examined the ggscout source code and found that the NHI inventory system has **strictly typed source types**:

```
hashicorpvault, k8s, awssecretsmanager, aws_iam, azurekeyvault,
akeyless, gitlabci, gcpsecretmanager, cyberarksaas,
cyberarkselfhosted, delineasecretserver, demo
```

There is **no "machine" or "workstation" source type** for local filesystem scanning.

### Current Payload Format

We're using the `demo` source type (the only generic one available):

```json
{
  "schema_version": "2025-12-02",
  "agent_version": "ggshield/1.x.x",
  "collected_on": "2025-12-06T...",
  "outputs": [
    {
      "source": {
        "type": "demo",
        "id": {"account_id": "hostname"},
        "name": "hostname"
      },
      "env": "development",
      "items": [
        {
          "source": {
            "type": "demo",
            "id": {"account_id": "hostname"}
          },
          "resource_key": "/path/to/file",
          "fetched_at": "...",
          "secrets": [
            {
              "hash": "scrypt-hash-of-secret",
              "length": 32,
              "sub_path": "SECRET_NAME",
              "detector": "Generic API Key",
              "validity": "valid",
              "leaked": false
            }
          ]
        }
      ]
    }
  ]
}
```

## Questions for GitGuardian Team

1. **What source type should ggshield use for local machine scanning?**
   - Is `demo` correct for this use case?
   - Should a new source type be added (e.g., `machine`, `workstation`, `ggshield`)?

2. **Is the payload format correct?**
   - The upload succeeds (returns `raw_data_id`) but data doesn't appear in UI
   - Is there additional processing/indexing required?
   - Is there a different endpoint for machine-type sources?

3. **What fields are required for the inventory to be searchable?**
   - We include: hash, length, sub_path (secret name), detector, validity, leaked
   - Are there required fields we're missing?

## Files Changed

### New Files
- `ggshield/cmd/machine/ping.py` - Test connectivity command
- `ggshield/cmd/machine/scan_and_send.py` - Scan and upload command
- `ggshield/verticals/machine/inventory/` - Inventory client and models
  - `client.py` - InventoryClient with NHIAuthError handling
  - `models.py` - InventoryPayload, SecretCollectionItem, SecretItem
  - `builder.py` - Functions to build payloads from scan/analysis results
- `tests/unit/cmd/machine/test_ping.py`
- `tests/unit/cmd/machine/test_scan_and_send.py`
- `tests/unit/verticals/machine/inventory/`

### Modified Files
- `ggshield/cmd/machine/__init__.py` - Register new commands
- `ggshield/core/config/config.py` - Add `nhi_api_key` property
- `ggshield/core/env_utils.py` - Add `GITGUARDIAN_NHI_API_KEY` to tracked vars
- `ggshield/verticals/machine/analyzer.py` - Minor fixes
- `ggshield/verticals/machine/output.py` - Minor fixes

## How to Test

```bash
# Set up NHI API key (service account with nhi:send-inventory scope)
export GITGUARDIAN_NHI_API_KEY="your-service-account-key"

# Test connectivity
pdm run ggshield machine ping

# Scan and upload (with dry-run to see payload)
pdm run ggshield machine scan-and-send --dry-run

# Full scan and upload
pdm run ggshield machine scan-and-send --ignore-config-exclusions
```

## API Endpoints

- **Ping**: `POST /v1/nhi/ping`
- **Upload**: `POST /v1/nhi/inventory/upload` (gzip compressed)

Both require:
- `Authorization: Token <NHI_API_KEY>`
- `Gg-Scout-Version: ggshield/x.x.x`
- `Gg-Scout-Platform: python`

## Next Steps

1. Get clarification from GitGuardian team on correct source type and payload format
2. Update the code to match expected format
3. Verify inventory appears in dashboard
4. Complete documentation and submit PR

## Branch

This work is saved on branch: `feat/machine-scan-and-send`
