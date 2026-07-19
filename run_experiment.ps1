param(
    [int]$Randomize = 1,
    [string]$Agent = ""
)

$ErrorActionPreference = "Stop"
$ResultsDir = "results"

$agents = @()
if ($Agent -ne "") {
    if ($Agent -notmatch "^[ABC]$") { Write-Error "Agent must be A, B, or C"; exit 1 }
    $agents = @($Agent)
} else {
    $agents = @("A", "B", "C")
}

Write-Output ""
Write-Output "=========================================="
Write-Output "  Sentra Controlled Experiment"
Write-Output "  Agents: $($agents -join ', ')  Randomize: $Randomize"
Write-Output "=========================================="
Write-Output ""

# Kill leftover agents
Get-Process -Name "python*" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "agent_" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$ports = @{ "A" = 8001; "B" = 8002; "C" = 8003 }
$postures = @{ "A" = "weak"; "B" = "medium"; "C" = "strong" }

foreach ($a in $agents) {
    $port = $ports[$a]
    $posture = $postures[$a]

    Write-Output "[Agent $a] Starting ($posture, port $port)..."
    $proc = Start-Process -FilePath "python" -ArgumentList "agents/agent_$($a.ToLower()).py" -PassThru -NoNewWindow
    Start-Sleep -Seconds 3

    $ready = $false
    for ($i = 1; $i -le 30; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:$port/health" -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        Write-Error "Agent $a failed to start on port $port"
        exit 1
    }
    Write-Output "  Agent $a ready."

    Write-Output "  Running experiment ($Randomize randomized run(s))..."
    python experiment_runner.py --agent $a --randomize $Randomize
    if ($LASTEXITCODE -ne 0) { Write-Error "Experiment for agent $a failed"; exit 1 }

    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Output ""
Write-Output "=========================================="
Write-Output "  Experiment Complete!"
Write-Output "=========================================="
Write-Output ""
if (Test-Path $ResultsDir) {
    Write-Output "Output files in $ResultsDir/:"
    Get-ChildItem -Path $ResultsDir | Select-Object Name, Length | Format-Table -AutoSize
}
Write-Output ""
