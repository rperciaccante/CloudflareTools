
New-NetFirewallRule -DisplayName "Allow Warp-Svc Inbound" -Direction Inbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe" -Action Allow -Profile Any 
New-NetFirewallRule -DisplayName "Allow Warp-Svc Outbound" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe" -Action Allow -Profile Any 
New-NetFirewallRule -DisplayName "Allow Warp-Dex Inbound" -Direction Inbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-dex.exe" -Action Allow -Profile Any

New-NetFirewallRule -DisplayName "Allow Warp-Dex Outbound" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-dex.exe" -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Allow Warp-Diag Inbound" -Direction Inbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-diag.exe" -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Allow Warp-Diag Outbound" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-diag.exe" -Action Allow -Profile Any
