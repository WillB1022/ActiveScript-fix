<# Modified by J. Orf on 08/03/22
    This will now attempt to search for the appropriate username
    This is only a recent issue as we have new employees who have incremented variables after their usernames or middle initials
    If the latter, a selection menu is presented
#>

$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())

if((Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value -contains 'vector-dc03.vector.local' -or '*')
{
 Write-Host -Object 'Wildcard or Vector present in TrustedHosts' -ForegroundColor Green
}
else
{
  Write-Host -Object 'Wildcard or Vector not present in TrustedHosts, adding' -ForegroundColor Yellow
  if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
  {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'Vector-DC03.vector.local' -Concatenate -Force
  }else
  {
    Start-Process -FilePath 'powershell' -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
  }   
}


$FileName = 'ActiveScript.exe'

$DirectoryName = Get-ChildItem -Path $HOME\AppData -Filter $FileName -Recurse | Select-Object -First 1 -ExpandProperty DirectoryName

$FilePath = $DirectoryName + '\' + $FileName

Copy-Item -Force  \\nas2\Software\ActiveScript\Application.config $DirectoryName

[string]$userName = 'vector\vuserlookup'
[string]$userPassword = 'ptYei3Pk8d4WLE'
[securestring]$secStringPassword = ConvertTo-SecureString -String $userPassword -AsPlainText -Force
[pscredential]$credObject = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($userName, $secStringPassword)

$leftPart = $env:username[0]
$rightPart = $env:username.Substring($env:username.IndexOf("$($env:username[0])")+2)

Write-Host -Object 'Finding Vector User(s)' -ForegroundColor Yellow
$vectorusers = Invoke-Command -Credential $credObject -ComputerName 'vector-dc03.vector.local' -ScriptBlock {
  Get-ADUser -SearchBase 'OU=Internal Users,DC=vector,DC=local'-Filter "sAMAccountName -like '$using:leftPart*$using:rightPart*'" | Select-Object -ExpandProperty SamAccountName
}

if($vectorusers.Count -gt 1)
{
  $items = $vectorusers | ForEach-Object -Begin {
    $i = 0
  } -Process {
    $i++
    [pscustomobject]@{
      ItemNumber = $i
      MenuItem   = $_
    }
  } -End {

  }
  $MyMenu = [pscustomObject]@{
    Title = 'Select the correct user'
    Items = $items
  }

  $hereMenu = @"
$($MyMenu.title)`n
"@
  foreach ($item in $MyMenu.Items) 
  {
    $hereMenu += "{0} - {1}`n" -f $item.ItemNumber, $item.MenuItem
  }
  $hereMenu += 'Enter a menu number or Q to quit'

  Clear-Host
  $r = Read-Host -Prompt $hereMenu
  if ($r -match '^q' -OR $r.length -eq 0) 
  {
    $Running = $False
    Write-Host -Object 'Exiting' -ForegroundColor green
    Return
  }
  elseif ( -Not ([int]$r -ge 1 -AND [int]$r -le $($MyMenu.Items.count)) ) 
  {
    Write-Warning -Message "Enter a menu choice between 1 and $($MyMenu.Items.count) or Q to quit"
  }
  else 
  {
    $vectoruser = $MyMenu.Items[$r-1].MenuItem
  }
}
else
{
  $vectoruser = $vectorusers
}

$Command = @('/C'
  "C:\Windows\System32\runas.exe /netonly /user:vector\$vectoruser" + ' ' + $FilePath
)

Start-Process -Verb runas -FilePath 'cmd.exe' -ArgumentList $Command