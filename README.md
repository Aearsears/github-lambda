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

## Environment & Configuration Management

-   Per-function environment variables stored securely
-   Secret management integration (Vault, AWS, GCP, Azure)
-   Configuration inheritance between functions
-   Encrypted local secret storage (AES-256-GCM)
-   Secret caching with configurable TTL

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

## Cold Start Optimization

The cold start optimization system provides cached dependency layers and function image prebuilding using GitHub Actions cache.

### Configuration

Set the following environment variables:

```bash
# Warm pool configuration
WARMPOOL_FILE=/path/to/warmpool.json       # Persistence file
WARMPOOL_MAX_SIZE=100                       # Maximum warm instances
WARMPOOL_ARTIFACT_DIR=.lambda-cache         # Artifact storage directory

# Prebuild configuration
PREBUILD_QUEUE_SIZE=100                     # Build queue size

# Disable cold start optimization (not recommended for production)
COLDSTART_DISABLED=true
```

### Warm Pool Management

The warm pool keeps function instances pre-warmed for faster cold starts.

#### Register Function for Warm Pool

```
POST /api/warmpool/functions
Content-Type: application/json

{
  "name": "my-function",
  "runtime": "python",
  "runtime_version": "3.11",
  "dependency_manager": "pip",
  "dependency_file": "requirements.txt",
  "prewarm_instances": 2,
  "idle_timeout": "5m"
}
```

Supported runtimes: `python`, `node`, `go`, `java`, `ruby`, `rust`, `dotnet`, `custom`

#### List Registered Functions

```
GET /api/warmpool/functions
```

#### Get Function Cache Configuration

Returns the GitHub Actions cache configuration for a function:

```
GET /api/warmpool/functions/{name}/cache-config
```

Response:

```json
{
    "function_name": "my-function",
    "runtime": "python",
    "cache_paths": ["~/.cache/pip", ".venv"],
    "key_template": "python-3.11-my-function-{{hashFiles('**/requirements*.txt')}}"
}
```

#### Generate Workflow Cache Step

Returns a GitHub Actions workflow step for caching dependencies:

```
GET /api/warmpool/functions/{name}/workflow-cache
```

Response:

```json
{
    "name": "Cache my-function dependencies",
    "uses": "actions/cache@v4",
    "with": {
        "path": ["~/.cache/pip", ".venv"],
        "key": "python-3.11-my-function-{{hashFiles('**/requirements*.txt')}}",
        "restore-keys": ["python-3.11-my-function-", "python-3.11-"]
    }
}
```

#### Warm Up Instances

```
POST /api/warmpool/instances/{name}/warmup?count=3
```

#### Check Cache Status

```
POST /api/warmpool/cache/check
Content-Type: application/json

{
  "function_name": "my-function",
  "dependency_hash": "abc123..."
}
```

Response:

```json
{
    "function_name": "my-function",
    "status": "hit",
    "artifact": {
        "cache_key": "python-3.11-my-function-abc123",
        "build_duration": "45s"
    },
    "time_saved": "45s"
}
```

#### Get Warm Pool Stats

```
GET /api/warmpool/stats
```

### Function Image Prebuilding

The prebuild system automatically builds and caches function container images.

#### Register Prebuild Specification

```
POST /api/prebuild/specs
Content-Type: application/json

{
  "function_name": "my-function",
  "image_name": "ghcr.io/myorg/my-function",
  "image_tag": "latest",
  "dockerfile": "Dockerfile",
  "build_context": ".",
  "platform": "linux/amd64",
  "enabled": true,
  "trigger_on_push": true,
  "trigger_files": ["requirements.txt", "package.json"],
  "layer_caching": {
    "enabled": true,
    "mode": "max",
    "github_actions_cache": true
  }
}
```

#### Trigger a Prebuild

```
POST /api/prebuild/trigger/{name}
```

#### Get Workflow Build Configuration

Returns the GitHub Actions workflow steps for building and caching:

```
GET /api/prebuild/workflow/{name}
```

Response:

```json
{
    "function_name": "my-function",
    "steps": [
        {
            "name": "Set up Docker Buildx",
            "uses": "docker/setup-buildx-action@v3"
        },
        {
            "name": "Cache Docker layers for my-function",
            "uses": "actions/cache@v4",
            "with": {
                "path": "/tmp/.buildx-cache",
                "key": "buildx-my-function-${{ github.sha }}"
            }
        },
        {
            "name": "Build and push my-function",
            "uses": "docker/build-push-action@v5",
            "with": {
                "context": ".",
                "file": "Dockerfile",
                "push": true,
                "tags": "ghcr.io/myorg/my-function:latest",
                "cache-from": "type=local,src=/tmp/.buildx-cache",
                "cache-to": "type=local,dest=/tmp/.buildx-cache-new,mode=max"
            }
        }
    ]
}
```

#### Get Latest Prebuilt Image

```
GET /api/prebuild/images/{name}/latest
```

#### List Builds

```
GET /api/prebuild/builds?function=my-function
```

#### Get Prebuild Stats

```
GET /api/prebuild/stats
```

Response:

```json
{
    "total_specs": 5,
    "total_builds": 42,
    "total_images": 15,
    "builds_by_status": {
        "succeeded": 38,
        "failed": 4
    },
    "average_build_duration": "2m30s",
    "cache_hit_rate": 0.85,
    "total_image_size": 1073741824
}
```

### GitHub Actions Workflow Integration

Use the generated cache configurations in your GitHub Actions workflows:

```yaml
name: Function Build

on:
    push:
        paths:
            - "functions/my-function/**"

jobs:
    build:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4

            # Fetch cache configuration from the server
            - name: Get cache config
              id: cache-config
              run: |
                  curl -H "Authorization: Bearer ${{ secrets.API_KEY }}" \
                    https://your-server/api/warmpool/functions/my-function/cache-config \
                    -o cache-config.json

            # Python dependency caching
            - uses: actions/cache@v4
              with:
                  path: |
                      ~/.cache/pip
                      .venv
                  key: python-3.11-my-function-${{ hashFiles('**/requirements*.txt') }}
                  restore-keys: |
                      python-3.11-my-function-
                      python-3.11-

            # Docker layer caching for image builds
            - uses: docker/setup-buildx-action@v3

            - uses: actions/cache@v4
              with:
                  path: /tmp/.buildx-cache
                  key: buildx-my-function-${{ github.sha }}
                  restore-keys: buildx-my-function-

            - uses: docker/build-push-action@v5
              with:
                  context: .
                  push: true
                  tags: ghcr.io/myorg/my-function:latest
                  cache-from: type=local,src=/tmp/.buildx-cache
                  cache-to: type=local,dest=/tmp/.buildx-cache-new,mode=max

            # GitHub Actions cache workaround
            - name: Move cache
              run: |
                  rm -rf /tmp/.buildx-cache
                  mv /tmp/.buildx-cache-new /tmp/.buildx-cache
```

### Runtime-Specific Cache Paths

The system automatically configures cache paths based on runtime:

| Runtime | Package Manager | Cache Paths                                   |
| ------- | --------------- | --------------------------------------------- |
| Python  | pip             | `~/.cache/pip`, `.venv`                       |
| Node.js | npm             | `~/.npm`, `node_modules`                      |
| Node.js | yarn            | `~/.cache/yarn`, `node_modules`               |
| Node.js | pnpm            | `~/.local/share/pnpm/store`, `node_modules`   |
| Go      | go mod          | `~/go/pkg/mod`, `~/.cache/go-build`           |
| Java    | Maven           | `~/.m2/repository`                            |
| Java    | Gradle          | `~/.gradle/caches`, `~/.gradle/wrapper`       |
| Ruby    | Bundler         | `vendor/bundle`                               |
| Rust    | Cargo           | `~/.cargo/bin`, `~/.cargo/registry`, `target` |
| .NET    | NuGet           | `~/.nuget/packages`                           |

### Cold Start Optimization Best Practices

1. **Pre-warm instances**: Use the warm-up API before expected traffic spikes
2. **Layer caching**: Enable Docker layer caching for image builds
3. **Dependency caching**: Use lockfiles (package-lock.json, go.sum) for consistent cache keys
4. **Scheduled prebuilds**: Configure scheduled builds during off-peak hours
5. **Monitor stats**: Regularly check cache hit rates and optimize accordingly
6. **Keep dependencies updated**: But use lockfiles for reproducible builds
