# CI only: tries the Samurai service socket as the current Windows account (PowerShell 7, .NET AF_UNIX)
# and writes "connected <response>" or "denied <error>" to -Out.
param([Parameter(Mandatory = $true)][string]$Out)
$socket = 'C:\ProgramData\SamuraiVPN\run\service.sock'
try {
    $client = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::Unix, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Unspecified)
    $client.Connect([System.Net.Sockets.UnixDomainSocketEndPoint]::new($socket))
    $request = '{"operation":"status","networkId":"' + [guid]::NewGuid() + '"}'
    [void]$client.Send([Text.Encoding]::UTF8.GetBytes($request))
    $client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
    $buffer = [byte[]]::new(65536); $response = ''
    while (($read = $client.Receive($buffer)) -gt 0) { $response += [Text.Encoding]::UTF8.GetString($buffer, 0, $read) }
    $client.Close()
    Set-Content -LiteralPath $Out -Value "connected $response"
} catch {
    Set-Content -LiteralPath $Out -Value "denied $($_.Exception.Message)"
}
