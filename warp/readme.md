
*Enabling Windows local firewall for the different components of the WARP client*

<table width=500>
  <thead>
    <td> Executable </td>
    <td> Direction </td>
    <td> Required? </td>
    <td> Command (run in admin powershell) </td>
  </thead>
  <tr>
    <td rowspan=2> warp-svc.exe </td>
    <td> Inbound </td>
    <td> Yes </td>
  <td>
        
  ```powershell
New-NetFirewallRule -DisplayName "Allow Warp-Svc Inbound" -Direction Inbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe" -Action Allow -Profile Any  ```
  ```
</td>
  </tr>
  <tr>
    
  <td> Outbound </td>
  <td> Yes </td>
  <td>
        
  ```powershell
New-NetFirewallRule -DisplayName "Allow Warp-Svc Outbound" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe" -Action Allow -Profile Any  ```
  ```
  </td>
  </tr>
    <tr>
    <td rowspan=2> warp-dex.exe </td>
    <td> Inbound </td>
    <td> Yes </td>
  <td>
        
  ```powershell
New-NetFirewallRule -DisplayName "Allow Warp-Dex Inbound" -Direction Inbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-dex.exe" -Action Allow -Profile Any  ```
  ```
  </td>
  </tr>
  <tr>
    
  <td> Outbound </td>
  <td> Yes </td>
  <td>
        
  ```powershell
  New-NetFirewallRule -DisplayName "Allow Warp-Dex Outbound" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-dex.exe" -Action Allow -Profile Any
  ```
    
  </td>
  </tr>
    </tr>
    <tr>
    <td rowspan=2> warp-diag.exe </td>
    <td> Inbound </td>
    <td> Yes </td>
  <td>
        
  ```powershell
New-NetFirewallRule -DisplayName "Allow Warp-Diag Inbound" -Direction Inbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-diag.exe" -Action Allow -Profile Any
  ```
  </td>
  </tr>
  <tr>
    
  <td> Outbound </td>
  <td> Yes </td>
  <td>
        
  ```powershell
New-NetFirewallRule -DisplayName "Allow Warp-Diag Outbound" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-diag.exe" -Action Allow -Profile Any

  ```
    
  </td>
  </tr>

</table>
