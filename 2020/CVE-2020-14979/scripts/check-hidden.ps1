# check-hidden.ps1 - List hidden Windows Updates
# Use wushowhide.diagcab to hide/unhide updates

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()

Write-Host ""
Write-Host "Checking hidden Windows Updates..."
Write-Host ""

$result = $searcher.Search('IsInstalled=0 and IsHidden=1')

if ($result.Updates.Count -eq 0) {
    Write-Host "No hidden updates found."
} else {
    Write-Host "Hidden updates: $($result.Updates.Count)"
    foreach($u in $result.Updates) {
        Write-Host "  - $($u.Title)"
    }
}

Write-Host ""
