# Software-only checks; never connects to or modifies a Nano.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$source = Split-Path $PSScriptRoot -Parent
function Invoke-Native {
    param([string]$Exe, [string[]]$ArgList)
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}
function Get-Sha256Hex {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead((Join-Path $source $Path))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Set-LfFile {
    param([string]$Path, [string[]]$Lines)
    [System.IO.File]::WriteAllText((Join-Path $source $Path), ($Lines -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
}
Push-Location $source
$old = @{}
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GORISCV64')) { $old[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
try {
    New-Item -ItemType Directory out -Force | Out-Null
    $env:GOOS=(& go env GOHOSTOS).Trim()
    $env:GOARCH=(& go env GOHOSTARCH).Trim()
    $env:CGO_ENABLED='0'
    [Environment]::SetEnvironmentVariable('GORISCV64',$null,'Process')
    Invoke-Native go @('mod','verify')
    $eventsText=@(& go test -count=1 -json ./...)
    $testExit=$LASTEXITCODE
    Set-LfFile 'out/go-tests.jsonl' $eventsText
    if($testExit -ne 0){ throw 'Tests failed; no target build attempted.' }
    $events=$eventsText | ForEach-Object { $_ | ConvertFrom-Json }
    $passed=@($events | Where-Object {$_.Action -eq 'pass' -and $_.Test}).Count
    Invoke-Native go @('vet','./...')
    $env:GOOS='linux'; $env:GOARCH='riscv64'; $env:GORISCV64='rva20u64'
    Invoke-Native go @('vet','./...')
    Invoke-Native go @('build','-trimpath','-o','out/nano-fido','./cmd/nano-fido')
    foreach($item in @(
        @{Package='./internal/nanokit'; Name='nanokit-riscv64.test'},
        @{Package='./ctap'; Name='ctap-riscv64.test'},
        @{Package='./ctap_hid'; Name='ctap-hid-riscv64.test'}
    )) { Invoke-Native go @('test','-c','-o',('out/'+$item.Name),$item.Package) }
    $info=@(& go version -m out/nano-fido)
    if($LASTEXITCODE -ne 0){ throw 'Cannot inspect build metadata.' }
    Set-LfFile 'out/build-info.txt' $info
    $hash=Get-Sha256Hex 'out/nano-fido'
    Set-LfFile 'out/SHA256SUMS.txt' @("$hash  nano-fido")
    $report=[ordered]@{
        target='linux/riscv64 rva20u64 CGO_ENABLED=0'
        goVersion=(& go version)
        hostTestsPassedIncludingSubtests=$passed
        binarySha256=$hash
        hardware='Not tested by this build script; see docs/TEST-STATUS.md for prior physical evidence.'
        certification='None; experimental software only.'
    } | ConvertTo-Json -Depth 4
    Set-LfFile 'out/validation.json' @($report)
    Write-Host "PASS: $passed host tests, host/target vet and RISC-V cross-build."
    Write-Host "SHA256: $hash"
} finally {
    foreach($name in $old.Keys){ [Environment]::SetEnvironmentVariable($name,$old[$name],'Process') }
    Pop-Location
}
