# Ram Antivirus Desktop Console — Testing & Integrity Verification Guide

This guide documents the verification standards, test pipelines, and fixture provenance for the Ram Antivirus Desktop application.

---

## 1. Test Suite Structure

The test suite is located in `Aegis.Tests` and contains **163 automated tests** covering:
- **`SchemaIntegrityTests.cs`**: Automated reflection test ensuring all response DTO properties match the official FastAPI OpenAPI 3.1 schema.
- **`RequestSchemaIntegrityTests.cs`**: Automated reflection test ensuring all POST/PUT/PATCH/DELETE request DTOs match OpenAPI schemas, including required field assertions and explicit `confirm` flags on destructive endpoints.
- **`SecretsSanitizationTests.cs`**: Security test asserting that zero fixtures contain active JWTs, live API keys, bot tokens, or webhook credentials.
- **`ContractDeserializationTests.cs`**: System.Text.Json deserialization tests validating real backend response payloads against C# models.
- **`LiveBackendSmokeTests.cs`**: End-to-end integration test against the running FastAPI backend (`http://127.0.0.1:8000`), testing 34 REST endpoints, WebSocket handshake (`auth` -> `auth_ok` -> `subscribe` -> `ping/pong`), and safe destructive guards.
- **ViewModel Tests**: Unit tests for every ViewModel validating initial loading, error states, 403 Forbidden handling, and destructive confirmation cancellation vs execution.

---

## 2. Fixture Ingestion & Provenance

All test fixtures located in `desktop-dotnet/Aegis.Tests/Fixtures/*.json` originate from either:
1. **Direct Backend Capture**: Live HTTP responses captured from the running FastAPI backend using `scripts/capture_real_fixtures.py` authenticated as `admin@aegis.local`.
2. **OpenAPI 3.1 Component Definitions**: Exported directly from the backend's `/openapi.json` route.

### Zero Hand-Written Fixtures Policy
No hand-written or fabricated dictionaries are permitted in `Aegis.Tests/Fixtures/`. Every fixture must be captured directly from a running backend instance or generated from the official OpenAPI schema.

### How to Re-Capture Fixtures
When the backend schema or routers change:
```bash
# 1. Start backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Run capture script
python scripts/capture_real_fixtures.py

# 3. Scrub secrets
python scripts/scrub_fixtures.py

# 4. Run verification tests
dotnet test desktop-dotnet/Aegis.Tests
```

---

## 3. Automated Schema Drift Detection

The reflection test `SchemaIntegrityTests.cs` and `RequestSchemaIntegrityTests.cs` inspect every public property on C# DTOs:
```csharp
[Theory]
[InlineData(typeof(UserLoginResponse), "UserLoginResponse")]
[InlineData(typeof(IncidentDto), "IncidentOut")]
[InlineData(typeof(KillProcessRequest), "KillProcessRequest")]
...
public void DtoProperties_MatchOpenApiSchemaProperties(Type dtoType, string schemaName)
```
If a field is renamed, added, or removed in the backend without updating the C# DTO, the build fails immediately in CI.

---

## 4. Running the Tests & Code Coverage

### Run All Unit & Schema Integrity Tests
```powershell
& "C:\Users\ADMIN\.dotnet\dotnet.exe" test desktop-dotnet/Aegis.Desktop.sln
```

### Run with Coverlet Code Coverage
```powershell
& "C:\Users\ADMIN\.dotnet\dotnet.exe" test desktop-dotnet/Aegis.Tests --collect:"XPlat Code Coverage"
```

### Run Live Backend Smoke Test
With the backend running at `http://127.0.0.1:8000`:
```powershell
& "C:\Users\ADMIN\.dotnet\dotnet.exe" test desktop-dotnet/Aegis.Tests --filter "FullyQualifiedName~LiveBackendSmokeTests"
```
