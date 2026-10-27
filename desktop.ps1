$ErrorActionPreference = 'Stop'
$java = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { 'java' }
& $java -jar (Join-Path $PSScriptRoot 'vpn-desktop/target/samurai-desktop.jar') @args
exit $LASTEXITCODE
