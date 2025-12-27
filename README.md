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
