# github-lambda

Using GitHub Actions as Lambda Functions

## Features

**Execution Model**

-   Event-driven invocation (HTTP requests, message queues, scheduled triggers)
-   Stateless compute - each invocation runs independently
-   Auto-scaling - automatically handles concurrent requests
-   Pay-per-execution pricing model

**Runtime Environment**

-   Support for multiple programming languages (Python, Node.js, Go, Java, etc.)
-   Configurable memory and CPU allocation
-   Execution time limits (typically 5-15 minutes)
-   Environment variables and secrets management

**Integration**

-   API Gateway/HTTP endpoints for external access
-   Integration with other cloud services (storage, databases, messaging)
-   Event source mappings for automatic triggering
-   Asynchronous and synchronous invocation modes

**Deployment & Management**

-   Code packaging and versioning
-   Alias management for different environments
-   Cold start optimization options
-   Logging and monitoring integration

**Security**

-   IAM/role-based access control
-   VPC networking support
-   Encryption at rest and in transit
-   Resource policies for function access

**9. Cold Start Optimization**

-   Cached dependency layers
-   Function image prebuilding
    **10. Environment & Configuration Management**

-   Per-function environment variables stored securely
-   Secret management integration (Vault, AWS, GCP, Azure)
-   Configuration inheritance between functions
-   Encrypted local secret storage (AES-256-GCM)
-   Secret caching with configurable TTL

## Environment & Configuration Management

The configuration management system provides secure per-function environment variables and integrates with popular secret management services.

### Configuration

Set the following environment variables:

```bash
# Encryption key for local secrets (required for storing secrets locally)
CONFIG_ENCRYPTION_KEY=your-strong-encryption-key

# Configuration file for persistence (optional)
CONFIG_FILE=/path/to/config.json

# HashiCorp Vault (optional)
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=your-vault-token
VAULT_NAMESPACE=your-namespace    # Enterprise only
VAULT_MOUNT_PATH=secret           # Default: secret

# AWS Secrets Manager (optional)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret

# GCP Secret Manager (optional)
GCP_PROJECT_ID=your-project

# Azure Key Vault (optional)
AZURE_KEY_VAULT_URL=https://vault.vault.azure.net
```

### API Endpoints

#### List Configured Functions

```
GET /config/functions
```

#### Get Function Configuration

```
GET /config/functions/{function_name}
```

#### Create Function Configuration

```
POST /config/function
Content-Type: application/json

{
  "function_name": "my-function",
  "inherit": ["base-config"]    // Optional: inherit from other configs
}
```

#### Set Environment Variable

```
POST /config/env
Content-Type: application/json

{
  "function_name": "my-function",
  "name": "DATABASE_URL",
  "value": "postgres://localhost/db",
  "description": "Database connection string",
  "required": true,
  "sensitive": true              // Masks value in logs
}
```

#### Set Secret (Stored Locally Encrypted)

```
POST /config/secret
Content-Type: application/json

{
  "function_name": "my-function",
  "name": "API_KEY",
  "value": "secret-key-value",
  "is_secret": true
}
```

#### Set External Secret Reference

```
POST /config/secret/ref
Content-Type: application/json

{
  "function_name": "my-function",
  "name": "DB_PASSWORD",
  "source": "vault",            // vault, aws, gcp, azure, env
  "key": "path/to/secret",
  "field": "password",          // For JSON secrets
  "version": "2"                // Optional: specific version
}
```

#### Set Global Environment Variable

```
POST /config/env/global
Content-Type: application/json

{
  "name": "ENVIRONMENT",
  "value": "production"
}
```

#### Delete Environment Variable

```
DELETE /config/env/delete?function=my-function&name=DATABASE_URL
```

#### Resolve Environment Variables

Returns the fully resolved environment variables for a function, showing the inheritance chain and where each variable comes from:

```
GET /config/env/resolve?function=my-function
```

Response:

```json
{
    "function_name": "my-function",
    "inheritance_chain": ["global", "base-config", "my-function"],
    "resolved_vars": {
        "ENVIRONMENT": {
            "name": "ENVIRONMENT",
            "value": "production",
            "source": "global",
            "is_secret": false,
            "required": false
        },
        "DATABASE_URL": {
            "name": "DATABASE_URL",
            "value": "[REDACTED]",
            "source": "my-function",
            "is_secret": true,
            "overridden_by": "my-function"
        }
    }
}
```

### Configuration Inheritance

Functions can inherit environment variables from parent configurations:

```
POST /config/inherit
Content-Type: application/json

{
  "function_name": "my-api-handler",
  "parents": ["base-api", "production"]
}
```

#### Get Inheritance Chain

```
GET /config/inherit/chain?function=my-function
```

Variables are resolved in order:

1. **Global environment variables** - Available to all functions
2. **Inherited configurations** - Resolved recursively, in order specified
3. **Function-specific variables** - Override inherited values

Example hierarchy:

```
global
  └── base-config
        ├── staging-config
        │     └── my-staging-function
        └── production-config
              └── my-production-function
```

### Configuration Validation

#### Basic Validation

```
GET /config/validate?function=my-function
```

#### Advanced Validation

```
GET /config/validate/advanced?function=my-function&strict=true&validate_secrets=true
```

Query parameters:

-   `strict=true` - Treat warnings as errors
-   `validate_secrets=true` - Verify secrets can be resolved
-   `resolve_env_vars=false` - Skip resolution of env vars
-   `required_vars=VAR1,VAR2` - Additional required variables
-   `forbidden_vars=VAR1,VAR2` - Variables that must not be present

Response includes:

```json
{
  "valid": true,
  "function_name": "my-function",
  "issues": [
    {
      "severity": "warning",
      "code": "POTENTIALLY_SENSITIVE",
      "message": "environment variable 'API_KEY' may contain sensitive data",
      "field": "API_KEY",
      "suggestion": "Mark this variable as a secret or set sensitive=true"
    }
  ],
  "resolved_env_vars": { ... },
  "inheritance_chain": ["global", "base-config", "my-function"],
  "summary": {
    "errors": 0,
    "warnings": 1,
    "info": 0,
    "total": 1
  }
}
```

#### Validate All Functions

```
GET /config/validate/all?strict=true
```

#### Deployment Readiness Check

Performs comprehensive pre-deployment validation:

```
GET /config/validate/deployment?function=my-function
```

Response:

```json
{
    "ready": true,
    "function_name": "my-function",
    "blockers": [],
    "warnings": [],
    "resolved_config": {
        "ENVIRONMENT": "production",
        "API_KEY": "[REDACTED]"
    },
    "checked_at": "2025-12-27T10:00:00Z"
}
```

### Validation Rules

The system validates:

| Code                      | Severity | Description                           |
| ------------------------- | -------- | ------------------------------------- |
| `CONFIG_NOT_FOUND`        | Error    | Function configuration doesn't exist  |
| `MISSING_SECRET_REF`      | Error    | Required secret has no reference      |
| `MISSING_REQUIRED_VALUE`  | Error    | Required env var has no value         |
| `INVALID_SECRET_SOURCE`   | Error    | Secret references unknown source      |
| `EMPTY_SECRET_KEY`        | Error    | Secret reference has empty key        |
| `SECRET_NOT_FOUND`        | Error    | Local secret not found                |
| `MISSING_PARENT_CONFIG`   | Error    | Inherited config doesn't exist        |
| `CIRCULAR_INHERITANCE`    | Error    | Circular inheritance detected         |
| `INVALID_VAR_NAME`        | Error    | Env var name not POSIX-compliant      |
| `RESERVED_PREFIX`         | Warning  | Uses reserved prefix (GITHUB\_, etc.) |
| `POTENTIALLY_SENSITIVE`   | Warning  | May contain sensitive data            |
| `VALUE_TOO_LONG`          | Warning  | Value exceeds 32KB                    |
| `PROVIDER_NOT_CONFIGURED` | Warning  | Secret provider not configured        |
| `EMPTY_VALUE`             | Info     | Non-required var has empty value      |

#### Export Configuration (Secrets Redacted)

```
GET /config/export
```

#### Clear Secret Cache

```
POST /config/cache/clear
```

### Secret Sources

| Source  | Description                             |
| ------- | --------------------------------------- |
| `local` | Locally encrypted secrets (AES-256-GCM) |
| `env`   | System environment variables            |
| `vault` | HashiCorp Vault                         |
| `aws`   | AWS Secrets Manager                     |
| `gcp`   | GCP Secret Manager                      |
| `azure` | Azure Key Vault                         |

### Usage in Functions

Environment variables are automatically injected into function invocations. The dispatch payload includes:

```json
{
    "function_name": "my-function",
    "version": 1,
    "invocation_id": "123456",
    "payload": "...",
    "env_vars": {
        "DATABASE_URL": "postgres://...",
        "API_KEY": "resolved-secret-value"
    }
}
```

In your GitHub Actions workflow, access these variables:

```yaml
- name: Run function
  env:
      DATABASE_URL: ${{ github.event.client_payload.env_vars.DATABASE_URL }}
      API_KEY: ${{ github.event.client_payload.env_vars.API_KEY }}
  run: |
      ./run-function.sh
```

### Security Considerations

1. **Encryption Key**: Use a strong, randomly generated key for `CONFIG_ENCRYPTION_KEY`
2. **Secret Rotation**: Use external secret managers (Vault, AWS, etc.) for automatic rotation
3. **Access Control**: Configuration endpoints require admin permissions
4. **Audit Logging**: All secret access is logged
5. **Cache TTL**: Adjust secret cache TTL based on security requirements
