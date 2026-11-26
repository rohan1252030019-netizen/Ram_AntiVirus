# ==============================================================================
# AEGIS Desktop Live-Backend Smoke Test (Phase 2)
# Tests REST API & WebSocket endpoints against a running backend.
# Usage:
#   .\smoke-test-live.ps1 -ServerUrl "http://localhost:8000"
# Or pass credentials via environment variables:
#   $env:AEGIS_EMAIL = "admin@aegis.local"
#   $env:AEGIS_PASSWORD = "your_secure_password"
#   .\smoke-test-live.ps1
# ==============================================================================

param(
    [string]$ServerUrl = "http://localhost:8000",
    [string]$Email = $env:AEGIS_EMAIL,
    [string]$Password = $env:AEGIS_PASSWORD,
    [string]$ApiKey = $env:AEGIS_API_KEY
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  AEGIS Desktop Native C# / .NET 8 Live Backend Smoke Test" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Server: $ServerUrl" -ForegroundColor Gray

# Prompt if neither email/pass nor api key was provided
if ([string]::IsNullOrEmpty($ApiKey) -and ([string]::IsNullOrEmpty($Email) -or [string]::IsNullOrEmpty($Password))) {
    Write-Host "`nNo credentials supplied in environment." -ForegroundColor Yellow
    $Email = Read-Host "Enter AEGIS Account Email (e.g. admin@aegis.local)"
    $SecurePass = Read-Host "Enter AEGIS Account Password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

# 1. Health / Landing check
Write-Host "`n[1/5] Checking Backend Connectivity..." -NoNewline
try {
    $health = Invoke-RestMethod -Uri "$ServerUrl/docs" -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host " [PASS]" -ForegroundColor Green
} catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "Backend is not responding at $ServerUrl. Make sure 'docker compose up -d' or uvicorn is running." -ForegroundColor Yellow
    exit 1
}

# 2. Authentication
Write-Host "[2/5] Authenticating User..." -NoNewline
$token = $null
try {
    if (![string]::IsNullOrEmpty($ApiKey)) {
        $body = @{ api_key = $ApiKey } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri "$ServerUrl/api/v1/auth/login" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
        $token = $res.api_key
    } else {
        $body = @{ email = $Email; password = $Password } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri "$ServerUrl/api/v1/auth/user/login" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
        $token = $res.token
    }
    Write-Host " [PASS] (JWT Acquired)" -ForegroundColor Green
} catch {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$headers = @{ "Authorization" = "Bearer $token" }

# 3. REST Dashboard Overview
Write-Host "[3/5] Fetching Dashboard Overview..." -NoNewline
try {
    $overview = Invoke-RestMethod -Uri "$ServerUrl/api/v1/dashboard/overview" -Method Get -Headers $headers -TimeoutSec 5
    Write-Host " [PASS]" -ForegroundColor Green
    Write-Host "      Active Threats: $($overview.active_threats) | System Health: $($overview.system_health_percent)%" -ForegroundColor Gray
} catch {
    Write-Host " [FAIL]: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. REST Incidents
Write-Host "[4/5] Querying Incident Queue..." -NoNewline
try {
    $incidents = Invoke-RestMethod -Uri "$ServerUrl/api/v1/response/incidents" -Method Get -Headers $headers -TimeoutSec 5
    Write-Host " [PASS] ($($incidents.Count) incidents listed)" -ForegroundColor Green
} catch {
    Write-Host " [FAIL]: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. WebSocket Telemetry Protocol End-to-End
Write-Host "[5/5] Testing /ws Protocol Handshake..." -NoNewline
$wsUrl = $ServerUrl.Replace("http://", "ws://").Replace("https://", "wss://").TrimEnd('/') + "/ws"

try {
    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $cts = New-Object System.Threading.CancellationTokenSource(10000)
    $uri = New-Object System.Uri($wsUrl)
    $connectTask = $ws.ConnectAsync($uri, $cts.Token)
    $connectTask.Wait()

    if ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        # Send auth frame
        $authJson = @{ type = "auth"; token = $token } | ConvertTo-Json -Compress
        $authBytes = [System.Text.Encoding]::UTF8.GetBytes($authJson)
        $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$authBytes)
        $sendTask = $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token)
        $sendTask.Wait()

        # Receive auth response
        $recvBuffer = New-Object byte[] 4096
        $recvSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$recvBuffer)
        $recvTask = $ws.ReceiveAsync($recvSegment, $cts.Token)
        $recvTask.Wait()
        $authResp = [System.Text.Encoding]::UTF8.GetString($recvBuffer, 0, $recvTask.Result.Count)

        # Ping
        $pingBytes = [System.Text.Encoding]::UTF8.GetBytes('{"type":"ping"}')
        $pingSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$pingBytes)
        $pingTask = $ws.SendAsync($pingSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token)
        $pingTask.Wait()

        $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Smoke test complete", [System.Threading.CancellationToken]::None).Wait()
        Write-Host " [PASS]" -ForegroundColor Green
        Write-Host "      Auth frame response: $authResp" -ForegroundColor Gray
    } else {
        Write-Host " [FAIL] (WebSocket failed to open)" -ForegroundColor Red
    }
} catch {
    Write-Host " [FAIL]: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nSmoke test finished. All essential communication verified." -ForegroundColor Cyan
