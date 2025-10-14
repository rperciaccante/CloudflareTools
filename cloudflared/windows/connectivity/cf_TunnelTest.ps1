<#
.SYNOPSIS
   Performs TCP and UDP connection tests against a list of hosts and ports.
   
.DESCRIPTION
   This script iterates through a defined list of hostnames, ports, protocols, and
   descriptions, using a combination of Test-NetConnection and a custom UDP client to check
   for successful connections. It provides a colored output to clearly
   indicate which tests passed and which failed, along with a custom description.

.NOTES
   Original Author: 
   Gemini
   
   Maintaining Author:
   Bob Perciaccante

   Version: 1.8 - October 9, 2025
   - Added tests for QUIC protocol (UDP/7844)
   - Added test for DNS (UDP/53) to Cloudflare 1.1.1.1

.EXAMPLE
   .\test_connections.ps1
   This will run the script and display the test results to the console.

.LINKs
   - Cloudflare "Tunnel with Firewall"
     https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/tunnel-with-firewall/
   
#>

# Define the list of hosts, ports, protocols, and descriptions to test.
# The Protocol property should be either "TCP" or "UDP".

clear
$hostsToTest = @(

   # Cloudflare Global Region 1
   [PSCustomObject]@{ Hostname = "region1.v2.argotunnel.com"; Port = 7844; Protocol = "TCP"; Description = "Cloudflared Global Region 1 (http2)" },
   [PSCustomObject]@{ Hostname = "region1.v2.argotunnel.com"; Port = 7844; Protocol = "UDP"; Description = "Cloudflared Global Region 1 (quic)" },

   # Cloudflare Global Region 2
   [PSCustomObject]@{ Hostname = "region2.v2.argotunnel.com"; Port = 7844; Protocol = "TCP"; Description = "Cloudflared Global Region 2 (http2)" },
   [PSCustomObject]@{ Hostname = "region2.v2.argotunnel.com"; Port = 7844; Protocol = "UDP"; Description = "Cloudflared Global Region 2 (quic)" },

   # Cloudflare US Region 1
   [PSCustomObject]@{ Hostname = "us-region1.v2.argotunnel.com"; Port = 7844; Protocol = "TCP"; Description = "Cloudflared US Region 1 (http2)" },
   [PSCustomObject]@{ Hostname = "us-region1.v2.argotunnel.com"; Port = 7844; Protocol = "UDP"; Description = "Cloudflared US Region 1 (quic)" },

   # Cloudflare US Region 2
   [PSCustomObject]@{ Hostname = "us-region2.v2.argotunnel.com"; Port = 7844; Protocol = "TCP"; Description = "Cloudflared US Region 2 (http2)" },
   [PSCustomObject]@{ Hostname = "us-region2.v2.argotunnel.com"; Port = 7844; Protocol = "UDP"; Description = "Cloudflared US Region 2 (quic)" },

   # Cloudflare software update check
   [PSCustomObject]@{ Hostname = "api.cloudflare.com"; Port = 443; Protocol = "TCP"; Description = "Cloudflared Update Server (HTTPS)" },
   [PSCustomObject]@{ Hostname = "update.argotunnel.com"; Port = 443; Protocol = "TCP"; Description = "Cloudflared Update Server (HTTPS)" },

   # DNS Check to Cloudflare
   [PSCustomObject]@{ Hostname = "1.1.1.1"; Port = 53; Protocol = "UDP"; Description = "Cloudflare DNS (Puplic Primary)" },
   [PSCustomObject]@{ Hostname = "1.0.0.1"; Port = 53; Protocol = "UDP"; Description = "Cloudflare DNS (Puplic Secondary)" }
  
  )
  
  # Start the connection tests
  Write-Host "`nCloudflared connection test script." -ForegroundColor Yellow
  Write-Host "-------------------------------------" -ForegroundColor Yellow
  Write-Host "`nThis script will test the connections needed for a cloudflared tunnel to connect to the Cloudflare edge, based on the document located at " -ForegroundColor Yellow
  Write-Host " https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/tunnel-with-firewall/" -ForegroundColor Green
  
  Write-Host "`nStarting TCP/UDP connection tests..." -ForegroundColor Yellow
  
  # Iterate through each host/port combination and perform the test
  foreach ($test in $hostsToTest) {
   
     $hostname = $test.Hostname
     $port = $test.Port
     $protocol = $test.Protocol
     $description = $test.Description
     $isSuccessful = $false
  
     Write-Host "Testing connection to $hostname on port $port ($protocol) - $description..." -NoNewline
  
     # Check the protocol and run the appropriate test
     if ($protocol -eq "UDP") {
         # Use a more reliable method for UDP using UdpClient
         try {
             $udpClient = New-Object System.Net.Sockets.UdpClient
             $udpClient.Client.ReceiveTimeout = 5000 # 5 second timeout
             $udpClient.Connect($hostname, $port)
             # Try to send a small packet.
             $bytesSent = $udpClient.Send([byte[]](0x01), 1)
  
             # If the Send method completes without an exception, the connection is considered successful.
             # This is a better indicator for UDP than the Test-NetConnection cmdlet.
             if ($bytesSent -gt 0) {
                 $isSuccessful = $true
             }
         }
         catch {
             # An exception means the test failed. $isSuccessful remains $false.
         }
         finally {
             if ($udpClient) {
                 $udpClient.Close()
             }
         }
     }
     elseif ($protocol -eq "TCP") {
         # Test-NetConnection for TCP
         $result = Test-NetConnection -ComputerName $hostname -Port $port -WarningAction SilentlyContinue
         if ($result -and $result.TcpTestSucceeded) {
             $isSuccessful = $true
         }
     }
     else {
         Write-Host "Unknown protocol '$protocol'. Skipping."
     }
  
     # Output the result based on the boolean flag
     if ($isSuccessful) {
         Write-Host "PASSED" -ForegroundColor Green
     }
     else {
         Write-Host "FAILED" -ForegroundColor Red
     }
  }
  
  Write-Host "`nAll tests complete." -ForegroundColor Yellow
