$ErrorActionPreference = 'Stop'
$java = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { 'java' }
Push-Location $PSScriptRoot
try {
    & $java scripts/PackageApplication.java @args
    exit $LASTEXITCODE
} finally { Pop-Location }
