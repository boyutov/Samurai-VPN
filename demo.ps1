$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$demoDir = Join-Path '.local' ('demo-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $demoDir | Out-Null
$javaBin = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { 'java' }
function Invoke-Client {
    & $javaBin -jar 'vpn-client/target/samurai-client.jar' @args
    if ($LASTEXITCODE -ne 0) { throw 'Client operation failed' }
}
Invoke-Client gen-admin --out "$demoDir/admin.token"
$server = $null
try {
    $server = Start-Process -FilePath $javaBin -ArgumentList @('-jar', 'vpn-server/target/samurai-server.jar', '--dev', '--admin-token-file', "$demoDir/admin.token") -PassThru -NoNewWindow -RedirectStandardOutput "$demoDir/server.log" -RedirectStandardError "$demoDir/server-error.log"
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($server.HasExited) { throw "Server failed; see $demoDir/server-error.log" }
        if ((Test-Path "$demoDir/server.log") -and (Select-String -Path "$demoDir/server.log" -Pattern 'control server listening' -Quiet)) { break }
        Start-Sleep -Milliseconds 100
    }
    Invoke-Client create-network --dev --server http://127.0.0.1:8787 --token-file "$demoDir/admin.token" --name Friends --out "$demoDir/owner.json"
    foreach ($person in @('alice', 'bob')) {
        Invoke-Client keygen --out "$demoDir/$person-key.json"
        Invoke-Client invite --dev --owner "$demoDir/owner.json" --out "$demoDir/$person-invite.json"
        Invoke-Client join --dev --invite "$demoDir/$person-invite.json" --identity "$demoDir/$person-key.json" --name $person --out "$demoDir/$person.json"
    }
    foreach ($person in @('alice', 'bob')) {
        Invoke-Client export --dev --session "$demoDir/$person.json" --out "$demoDir/$person.conf"
    }
    Invoke-Client peers --dev --session "$demoDir/alice.json"
    Write-Output "Demo complete. Private local files: $demoDir. No tunnel was activated."
} finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
}
