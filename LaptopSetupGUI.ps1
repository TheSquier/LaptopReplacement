
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
$LaptopSetup = New-Object -TypeName System.Windows.Forms.Form
[System.Windows.Forms.Button]$Backup = $null
[System.Windows.Forms.Label]$label1 = $null
[System.Windows.Forms.TextBox]$textBox1 = $null
[System.Windows.Forms.TextBox]$StatusBackup = $null
[System.Windows.Forms.TextBox]$StatusRestore = $null
[System.Windows.Forms.ProgressBar]$progress = $null
[System.Windows.Forms.Button]$Restore = $null
function InitializeComponent
{
#Component intialization
$Backup = (New-Object -TypeName System.Windows.Forms.Button)
$label1 = (New-Object -TypeName System.Windows.Forms.Label)
$textBox1 = (New-Object -TypeName System.Windows.Forms.TextBox)
$StatusBackup = (New-Object -TypeName System.Windows.Forms.TextBox)
$StatusRestore = (New-Object -TypeName System.Windows.Forms.TextBox)
$Restore = (New-Object -TypeName System.Windows.Forms.Button)
$progress = (New-Object -TypeName System.Windows.Forms.ProgressBar)
$LaptopSetup.SuspendLayout()
#
#Backup button initialization
#
$Backup.BackColor = [System.Drawing.SystemColors]::ControlLight
$Backup.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]45,[System.Int32]420))
$Backup.Name = [System.String]'Backup'
$Backup.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]161,[System.Int32]52))
$Backup.TabIndex = [System.Int32]1
$Backup.Text = [System.String]'Backup - Step 1 - Old Laptop'
$Backup.UseVisualStyleBackColor = $false
$Backup.add_Click($Backup_Click)
#
#label1 for app lable 
#
$label1.AutoSize = $true
$label1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]20,[System.Int32]22))
$label1.Name = [System.String]'label1'
$label1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]0,[System.Int32]13))
$label1.TabIndex = [System.Int32]2
#
#textBox1 text box to give instructions on usage
#
$textBox1.Enabled = $false
$textBox1.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Microsoft Sans Serif',[System.Single]13))
$textBox1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]45,[System.Int32]34))
$textBox1.Multiline = $true
$textBox1.Name = [System.String]'textBox1'
$textBox1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]509,[System.Int32]291))
$textBox1.TabIndex = [System.Int32]3
$textBox1.Text = 'Thank you for selecting the self-directed laptop setup option. To begin, ensure that this program is running on the old laptop and then click the "Backup – Step 1 – Old Laptop” button. After you have let this run, please boot up your new laptop and run this program and then on the new laptop select “Restore – Step 2 – New laptop” and let it run. Once it is completed, you can close the application and begin normal use!
    
Please note that during the process, the window may freeze. This is normal. Please wait for it to continue.

For the restore script, step 2, please restart your computer after it is complete. '
$textBox1.add_TextChanged($textBox1_TextChanged)
#
#StatusBackup text box to give status on backup
#
$StatusBackup.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]53,[System.Int32]478))
$StatusBackup.Name = [System.String]'StatusBackup'
$StatusBackup.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]139,[System.Int32]20))
$StatusBackup.TabIndex = [System.Int32]4
$StatusBackup.add_TextChanged($textBox2_TextChanged)
#
#StatusRestore text box to give status on restore
#

$StatusRestore.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]405,[System.Int32]477))
$StatusRestore.Name = [System.String]'StatusRestore'
$StatusRestore.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]135,[System.Int32]20))
$StatusRestore.TabIndex = [System.Int32]5
#
#Restore button intitialization
#
$Restore.BackColor = [System.Drawing.SystemColors]::ControlLight
$Restore.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]393,[System.Int32]419))
$Restore.Name = [System.String]'Restore'
$Restore.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]161,[System.Int32]52))
$Restore.TabIndex = [System.Int32]6
$Restore.Text = [System.String]'Restore - Step 2 - New Laptop'
$Restore.UseVisualStyleBackColor = $false
$Restore.add_Click($Restore_Click)
#
#progress bar initialization 
#
$progress.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]53,[System.Int32]531))
$progress.Name = [System.String]'progress'
$progress.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]487,[System.Int32]37))
$progress.TabIndex = [System.Int32]7
#
#LaptopSetup box initialization
#
$LaptopSetup.ClientSize = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]597,[System.Int32]612))
$LaptopSetup.Controls.Add($progress)
$LaptopSetup.Controls.Add($Restore)
$LaptopSetup.Controls.Add($StatusRestore)
$LaptopSetup.Controls.Add($StatusBackup)
$LaptopSetup.Controls.Add($textBox1)
$LaptopSetup.Controls.Add($label1)
$LaptopSetup.Controls.Add($Backup)
$LaptopSetup.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Fixed3D
$LaptopSetup.Name = [System.String]'GEHALaptopSetup'
$LaptopSetup.Text = [System.String]' '
$LaptopSetup.Text = [System.String]' Laptop Replacement Tool'
$LaptopSetup.add_Load($Form1_Load)
$LaptopSetup.ResumeLayout($false)
$LaptopSetup.PerformLayout()
Add-Member -InputObject $LaptopSetup -Name Backup -Value $Backup -MemberType NoteProperty
Add-Member -InputObject $LaptopSetup -Name label1 -Value $label1 -MemberType NoteProperty
Add-Member -InputObject $LaptopSetup -Name textBox1 -Value $textBox1 -MemberType NoteProperty
Add-Member -InputObject $LaptopSetup -Name StatusBackup -Value $StatusBackup -MemberType NoteProperty
Add-Member -InputObject $LaptopSetup -Name StatusRestore -Value $StatusRestore -MemberType NoteProperty
Add-Member -InputObject $LaptopSetup -Name progress -Value $progress -MemberType NoteProperty
Add-Member -InputObject $LaptopSetup -Name Restore -Value $Restore -MemberType NoteProperty
}

#Restore function for when user clicks the restore button on the menu
$Restore_Click = {
	$StatusRestore.text =  "Inprogress..."
    $Backup.Enabled = $false
    $Restore.Enabled = $false
    function Set-FTA { #this function sets up the ability to set a default app (Adobe)

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,
      
    [String]
    $Icon,

    [switch]
    $DomainSID
  )
  
  if (Test-Path -Path $ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
  }

  Write-Verbose "ProgId: $ProgId"
  Write-Verbose "Extension/Protocol: $Extension"

  
  #Write required Application Ids to ApplicationAssociationToasts
  #When more than one application associated with an Extension/Protocol is installed ApplicationAssociationToasts need to be updated
  function local:Write-RequiredApplicationAssociationToasts {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension
    )
    
    try {
      $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
      [Microsoft.Win32.Registry]::SetValue($keyPath, $ProgId + "_" + $Extension, 0x0) 
      Write-Verbose ("Write Reg ApplicationAssociationToasts OK: " + $ProgId + "_" + $Extension)
    }
    catch {
      Write-Verbose ("Write Reg ApplicationAssociationToasts FAILED: " + $ProgId + "_" + $Extension)
    }
    
    $allApplicationAssociationToasts = Get-ChildItem -Path HKLM:\SOFTWARE\Classes\$Extension\OpenWithList\* -ErrorAction SilentlyContinue | 
    ForEach-Object {
      "Applications\$($_.PSChildName)"
    }

    $allApplicationAssociationToasts += @(
      ForEach ($item in (Get-ItemProperty -Path HKLM:\SOFTWARE\Classes\$Extension\OpenWithProgids -ErrorAction SilentlyContinue).PSObject.Properties ) {
        if ([string]::IsNullOrEmpty($item.Value) -and $item -ne "(default)") {
          $item.Name
        }
      })

    
    $allApplicationAssociationToasts += Get-ChildItem -Path HKLM:SOFTWARE\Clients\StartMenuInternet\* , HKCU:SOFTWARE\Clients\StartMenuInternet\* -ErrorAction SilentlyContinue | 
    ForEach-Object {
    (Get-ItemProperty ("$($_.PSPath)\Capabilities\" + (@("URLAssociations", "FileAssociations") | Select-Object -Index $Extension.Contains("."))) -ErrorAction SilentlyContinue).$Extension
    }
    
    $allApplicationAssociationToasts | 
    ForEach-Object { if ($_) {
        if (Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts $_"_"$Extension -Value 0 -Type DWord -ErrorAction SilentlyContinue -PassThru) {
          Write-Verbose  ("Write Reg ApplicationAssociationToastsList OK: " + $_ + "_" + $Extension)
        }
        else {
          Write-Verbose  ("Write Reg ApplicationAssociationToastsList FAILED: " + $_ + "_" + $Extension)
        }
      } 
    }

  }

  function local:Update-RegistryChanges {
    $code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
'@ 

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {} 
  }
  

  function local:Set-Icon {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Icon
    )

    try {
      $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\DefaultIcon"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "", $Icon) 
      Write-Verbose "Write Reg Icon OK"
      Write-Verbose "Reg Icon: $keyPath"
    }
    catch {
      Write-Verbose "Write Reg Icon FAILED"
    }
  }


  function local:Write-ExtensionKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )
    

    function local:Remove-UserChoiceKey {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Key
      )

      $code = @'
      using System;
      using System.Runtime.InteropServices;
      using Microsoft.Win32;
      
      namespace Registry {
        public class Utils {
          [DllImport("advapi32.dll", SetLastError = true)]
          private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
      
          [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
          private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);
  
          public static void DeleteKey(string key) {
            UIntPtr hKey = UIntPtr.Zero;
            RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
            RegDeleteKey((UIntPtr)0x80000001u, key);
          }
        }
      }
'@
  
      try {
        Add-Type -TypeDefinition $code
      }
      catch {}

      try {
        [Registry.Utils]::DeleteKey($Key)
      }
      catch {} 
    } 

    
    try {
      $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
      Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
      Remove-UserChoiceKey $keyPath
    }
    catch {
      Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
    }
  

    try {
      $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
      [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
      Write-Verbose "Write Reg Extension UserChoice OK"
    }
    catch {
      throw "Write Reg Extension UserChoice FAILED"
    }
  }


  function local:Write-ProtocolKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Protocol,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )
      

    try {
      $keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
      Write-Verbose "Remove Protocol UserChoice Key If Exist: $keyPath"
      Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
    
    }
    catch {
      Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
    }
  

    try {
      $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
      [Microsoft.Win32.Registry]::SetValue( $keyPath, "Hash", $ProgHash)
      [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
      Write-Verbose "Write Reg Protocol UserChoice OK"
    }
    catch {
      throw "Write Reg Protocol UserChoice FAILED"
    }
    
  }

  
  function local:Get-UserExperience {
    [OutputType([string])]
    $hardcodedExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
    $userExperienceSearch = "User Choice set via Windows User Experience"
    $userExperienceString = ""
    $user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
    $fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $binaryReader = New-Object System.IO.BinaryReader($fileStream)
    [Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
    $fileStream.Close()
    $dataString = [Text.Encoding]::Unicode.GetString($bytesData)
    $position1 = $dataString.IndexOf($userExperienceSearch)
    $position2 = $dataString.IndexOf("}", $position1)
    try {
      $userExperienceString = $dataString.Substring($position1, $position2 - $position1 + 1)
    }
    catch {
      $userExperienceString = $hardcodedExperience
    }
    Write-Output $userExperienceString
  }
  

  function local:Get-UserSid {
    [OutputType([string])]
    $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
    Write-Output $userSid
  }

  #use in this special case
  #https://github.com/DanysysTeam/PS-SFTA/pull/7
  function local:Get-UserSidDomain {
    if (-not ("System.DirectoryServices.AccountManagement" -as [type])) {
      Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    [OutputType([string])]
    $userSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.Value.ToLower()
    Write-Output $userSid
  }



  function local:Get-HexDateTime {
    [OutputType([string])]

    $now = [DateTime]::Now
    $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $dateTime.ToFileTime()
    $hi = ($fileTime -shr 32)
    $low = ($fileTime -band 0xFFFFFFFFL)
    $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
    Write-Output $dateTimeHex
  }
  
  function Get-Hash {
    [CmdletBinding()]
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [string]
      $BaseInfo
    )


    function local:Get-ShiftRight {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $iValue, 
            
        [Parameter( Position = 1, Mandatory = $true)]
        [int] $iCount 
      )
    
      if ($iValue -band 0x80000000) {
        Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
      }
      else {
        Write-Output  ($iValue -shr $iCount)
      }
    }
    

    function local:Get-Long {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [byte[]] $Bytes,
    
        [Parameter( Position = 1)]
        [int] $Index = 0
      )
    
      Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
    }
    

    function local:Convert-Int32 {
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $Value
      )
    
      [byte[]] $bytes = [BitConverter]::GetBytes($Value)
      return [BitConverter]::ToInt32( $bytes, 0) 
    }

    [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
    $bytesBaseInfo += 0x00, 0x00  
    
    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
    
    $lengthBase = ($baseInfo.Length * 2) + 2 
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
    $base64Hash = ""

    if ($length -gt 1) {
    
      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }
    
      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1
    
      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
        $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
        $map.PDATA = $map.PDATA + 8
        $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
        $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
        $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
        $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
        $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
        $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
        $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }

      [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 0)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 4)
    
      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }
    
      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1

      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
        $map.PDATA = $map.PDATA + 8
        $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
        $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
        $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
        $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
        $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
        $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
        $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
        $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
        $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3) 
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }
    
      $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 8)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 12)
    
      [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
      $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
    
      $buffer = [BitConverter]::GetBytes($hashValue1)
      $buffer.CopyTo($outHashBase, 0)
      $buffer = [BitConverter]::GetBytes($hashValue2)
      $buffer.CopyTo($outHashBase, 4)
      $base64Hash = [Convert]::ToBase64String($outHashBase) 
    }

    Write-Output $base64Hash
  }

  Write-Verbose "Getting Hash For $ProgId   $Extension"
  If ($DomainSID.IsPresent) { Write-Verbose  "Use Get-UserSidDomain" } Else { Write-Verbose  "Use Get-UserSid" } 
  $userSid = If ($DomainSID.IsPresent) { Get-UserSidDomain } Else { Get-UserSid } 
  $userExperience = Get-UserExperience
  $userDateTime = Get-HexDateTime
  Write-Debug "UserDateTime: $userDateTime"
  Write-Debug "UserSid: $userSid"
  Write-Debug "UserExperience: $userExperience"

  $baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
  Write-Verbose "baseInfo: $baseInfo"

  $progHash = Get-Hash $baseInfo
  Write-Verbose "Hash: $progHash"
  
  #Write AssociationToasts List
  Write-RequiredApplicationAssociationToasts $ProgId $Extension

  #Handle Extension Or Protocol
  if ($Extension.Contains(".")) {
    Write-Verbose "Write Registry Extension: $Extension"
    Write-ExtensionKeys $ProgId $Extension $progHash

  }
  else {
    Write-Verbose "Write Registry Protocol: $Extension"
    Write-ProtocolKeys $ProgId $Extension $progHash
  }

   
  if ($Icon) {
    Write-Verbose  "Set Icon: $Icon"
    Set-Icon $ProgId $Icon
  }

  Update-RegistryChanges 

} 
Function Laptop-Restore {


#get current logged in user...
$loggedInUser = $clockID



#local profile path...
$localProfileChrome = "C:\Users\$($loggedInUser)\AppData\Local\Google\Chrome\User Data\Default"
$localProfileEdge = "C:\Users\$($loggedInUser)\AppData\Local\Microsoft\Edge\User Data\Default"
$localProfileTaskbar = "C:\Users\$($loggedInUser)\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
$localProfileSignature = "C:\Users\$($loggedInUser)\AppData\roaming\Microsoft\Signatures"

#WEB BROWSER SCRIPT

#Close all browser windows...
    Get-Process -Name Chrome | Stop-Process
    Get-Process -Name iexplore | Stop-Process
    Get-Process -Name msedge | Stop-Process

#copy Chrome Favorites to local profile...
    Get-ChildItem -Path 'U:\Laptop_Backup\Chrome\User Data\Default' | Copy-Item -Destination $localProfileChrome -Recurse -Force


#Copy Internet Explorer favorites from U Drive to Local...
    Get-ChildItem -Path U:\Laptop_Backup\IE\ | Copy-Item -Destination C:\Users\$($loggedInUser)\Favorites -Recurse -Force

#Copy Edge favorites from local to U Drive...
    Get-ChildItem -Path U:\Laptop_Backup\Edge\ | Copy-Item -Destination $localProfileEdge -Recurse -Force

#AVAYA SCRIPT
    
#local profile path...
$localProfileAvaya = "C:\Users\$($loggedInUser)\AppData\Roaming\Avaya"

#Copy Avaya profile contents...
   
    #create local profile Path...
    New-Item -Path $localProfileAvaya -ItemType Directory -Force -Confirm:$false

    #copy citrix profile contents to local profile...
    Get-ChildItem -Path U:\Laptop_Backup\Avaya\ | Copy-Item -Destination $localProfileAvaya -Recurse -Force

#Copy Pinned Taskbar Items...

    Get-ChildItem -Path U:\Laptop_Backup\Taskbar\Shortcuts\ | Copy-Item -Destination $localProfileTaskbar -Recurse -Force
    Invoke-Command {Reg Import U:\Laptop_Backup\Taskbar\Reg\Taskbar.reg}

#Copy Outlook Signatures...

    Get-ChildItem -Path U:\Laptop_Backup\Outlook\ | Copy-Item -Destination $localProfileSignature -Recurse -Force
Start-Process -FilePath "cmd.exe" -ArgumentList "/c reg.exe import `"U:\Laptop_Backup\outlook.reg`"" -Wait -passthru
Remove-ItemProperty -Path 'Registry::HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup' -Name 'First-Run'
New-ItemProperty -Path 'Registry::HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup' -Name 'First-Run' -PropertyType Binary -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup\' -Name First-Run)
#MACESS UPLOADS SCRIPT

#Test for Macess Uploads folder, and if found...
if (Test-Path -Path 'U:\Macess Uploads') { 

#Create Shortcut to the Working folder on the local Desktop...
$wshshell = New-Object -ComObject WScript.Shell
$desktop = [System.Environment]::GetFolderPath('Desktop')
  $lnk = $wshshell.CreateShortcut($desktop+"\Macess Uploads.lnk")
  $lnk.TargetPath = "U:\Macess Uploads"
  $lnk.Save() 
  }}
Function Write-Log {

   [CmdletBinding()]

   Param(

 

   [Parameter(Mandatory=$True)]

   [string]

   $Message,

 

   [Parameter(Mandatory=$False)]

   [string]

   $logfile

   )

 

   $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")

   $Line = "$Stamp $Message"

   If($logfile) {

       Add-Content $logfile -Value $Line

   }

   Else {

       Write-Output $Line

   }

}
Function Kill-MS {
#function to close out microsoft apps
Get-Process -Name "*Teams*" | Stop-Process -Confirm:$false  -erroraction 'silentlycontinue'
Get-Process -Name "*Word*" | Stop-Process -Confirm:$false  -erroraction 'silentlycontinue'
Get-Process -Name "*Excel*" | Stop-Process -Confirm:$false  -erroraction 'silentlycontinue'
Get-Process -Name "*Edge*" | Stop-Process -Confirm:$false  -erroraction 'silentlycontinue'
Get-Process -Name "*Outlook*" | Stop-Process -Confirm:$false  -erroraction 'silentlycontinue'
}    
$clockID = $env:UserName #gets username
$date = Get-Date -Format "MM-dd-yyyy" #gets date for a variable
$logfile = "<log location>"
$ErrorActionPreference = 'silentlycontinue' #this will stop unnecessary errors from displaying
Write-Log "Clock ID = $($ClockID)" $logfile
Write-Log "Computer Name: $($env:computername)" $logfile
clear-host
$progress.value =  10
gpupdate /force #force a group policy update
$progress.value =  50
Write-Log "Group Policy update ran." $logfile
#To Find Devices to disable run Get-PnpDevice -FriendlyName "*Smart Sound Technology*" |Export-csv -path "U:\output.csv"
Start-Process powershell -Verb RunAs {Disable-PnpDevice "INTELAUDIO\CTLR_DEV_A0C8&LINKTYPE_06&DEVTYPE_06&VEN_8086&DEV_AE50&SUBSYS_0A201028&REV_0001\0601" -Confirm:$false} #Disables Intell Smartsound Drivers for USB
Start-Process powershell -Verb RunAs {Disable-PnpDevice "INTELAUDIO\CTLR_DEV_51C8&LINKTYPE_03&DEVTYPE_00&VEN_8086&DEV_AE30&SUBSYS_0B041028&REV_0001\5&11D13EDA&0&0000" -Confirm:$false} #Disables Intell Smartsound Drivers for Bluetooth
Start-Process powershell -Verb RunAs {Disable-NetAdapterBinding -Name * -ComponentID 'ms_tcpip6' -Confirm:$false} #Disable IPV6 adapters.

$progress.value =  65
clear-host
Write-Log "Problem Drivers disabled" $logfile
Set-FTA AcroExch.Document.DC .pdf
Write-Log "Adobe Acrobat set as default PDF reader" $logfile
$progress.value =  70
Start-Sleep -s 2
#configure outlook
Start-Process powershell -Verb RunAs {Start-Process -FilePath "cmd.exe" -ArgumentList "/c reg.exe import `"U:\Laptop_Backup\outlook.reg`"" -Wait -passthru}
Start-Process powershell -Verb RunAs {Remove-ItemProperty -Path 'Registry::HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup' -Name 'First-Run'}
Start-Process powershell -Verb RunAs {New-ItemProperty -Path 'Registry::HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup' -Name 'First-Run' -PropertyType Binary -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup\' -Name First-Run)}
start outlook
clear-host    
     #this runs the restore script which will restore from the backup stored in the U drive.
    starrt-sleep -s 2
    Laptop-Restore
Start-Process powershell -Verb RunAs {New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Google\Chrome" -Name "BookmarkBarEnabled" -Value "1"-PropertyType "DWORD"}
Start-Process powershell -Verb RunAs {New-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Edge" -Name "FavoritesBarEnabled" -Value "1" -PropertyType "DWORD"}
Start-Process powershell -Verb RunAs {Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Google\Chrome" -Name "BookmarkBarEnabled" -Value "1"}
Start-Process powershell -Verb RunAs {Set-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Edge" -Name "FavoritesBarEnabled" -Value "1"}

    $progress.value =  85
    Write-Log "Restore Script ran." $logfile
    clear
clear-host
    Start-Sleep -s 2    
    	try {
           Test-Connection 8.8.8.8 -ErrorAction stop |Out-Null #Tests ability to connect to the internet
           Write-Log "Successfully Contacted Internet" $logfile}
    	   Catch {
    		Write-Log "!!Failed to connect to internet" $logfile}
       $progress.value =  98
     try {
        Test-Connection google.com -ErrorAction stop | Out-Null #tests ability to resolve DNS names
        Write-Log "Successfully resolved DNS" $logfile
        }
    Catch {
    Write-Log "!!Failed to resolve DNS" $logfile
    }
Write-Host "Testing Complete."
start-sleep -s 1
$progress.value =  100
$StatusRestore.text =  "Complete!"
}
#backup function called when the user picks backup from the menu
$Backup_Click = {
	$StatusBackup.text =  "Inprogress..."
    $Restore.Enabled = $false
    $Backup.Enabled = $false
	$ErrorActionPreference = "SilentlyContinue"
Start-Job -ScriptBlock {
Try {
Test-Path -Path "U:\Laptop_Backup" -ErrorAction stop | Out-Null
Get-ChildItem -Path "U:\Laptop_Backup" -ErrorAction stop | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction stop | Out-Null
Remove-Item -Path "U:\Laptop_Backup" -Confirm:$false -Force -ErrorAction stop | Out-Null
}
Catch {

}
#get current logged in user...
$loggedInUser = $env:UserName
}
$StatusBackup.text =  "Inprogress..."
    $progress.value =  10
Start-Job -ScriptBlock {
$loggedInUser = $env:UserName
#WEB BROWSER SCRIPT

#Close all browser windows...
    Get-Process -Name Chrome | Stop-Process
    Get-Process -Name iexplore | Stop-Process
    Get-Process -Name msedge | Stop-Process
$ErrorActionPreference = "SilentlyContinue"
#local profile path...
$localProfileChrome = "C:\Users\$($loggedInUser)\AppData\Local\Google\Chrome\User Data\Default"
$localProfileEdge = "C:\Users\$($loggedInUser)\AppData\Local\Microsoft\Edge\User Data\Default"
$localProfileTaskbar = "C:\Users\$($loggedInUser)\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
$localProfileSignature = "C:\Users\$($loggedInUser)\AppData\roaming\Microsoft\Signatures"

#copy Local Chrome Favorites to U drive...
    New-Item -Path 'U:\Laptop_Backup\Chrome\User Data\Default' -ItemType Directory -Force -Confirm:$false
    Get-ChildItem -Path $localProfileChrome\Bookmarks | Copy-Item -Destination 'U:\Laptop_Backup\Chrome\User Data\Default' -Recurse -Force
    Get-ChildItem -Path $localProfileChrome\Bookmarks.bak | Copy-Item -Destination 'U:\Laptop_Backup\Chrome\User Data\Default' -Recurse -Force
}
    $progress.value = 25
Start-Job -ScriptBlock {v
$loggedInUser = $env:UserName
#Copy Local Internet Explorer favorites to U drive...
    New-Item -Path U:\Laptop_Backup\IE -ItemType Directory -Force -Confirm:$false
    Get-ChildItem -Path C:\Users\$($loggedInUser)\Favorites | Copy-Item -Destination U:\Laptop_Backup\IE -Recurse -Force
}

    $progress.value = 35
Start-Job -ScriptBlock {
$loggedInUser = $env:UserName
#Copy Edge favorites from local to U Drive...
    New-Item -Path U:\Laptop_Backup\Edge -ItemType Directory -Force -Confirm:$false
    Get-ChildItem -Path $localProfileEdge\bookmarks | Copy-Item -Destination U:\Laptop_Backup\Edge\ -Recurse -Force
    Get-ChildItem -Path $localProfileEdge\bookmarks.bak | Copy-Item -Destination U:\Laptop_Backup\Edge\ -Recurse -Force
    Get-ChildItem -Path $localProfileEdge\bookmarks.msbak | Copy-Item -Destination U:\Laptop_Backup\Edge\ -Recurse -Force
}
    $progress.value = 50
Start-Job -ScriptBlock {
$loggedInUser = $env:UserName
#Copy Pinned Taskbar Items...
    New-Item -Path U:\Laptop_Backup\Taskbar -ItemType Directory -Force -Confirm:$false
    New-Item -Path U:\Laptop_Backup\Taskbar\Reg -ItemType Directory -Force -Confirm:$false
    New-Item -Path U:\Laptop_Backup\Taskbar\Shortcuts -ItemType Directory -Force -Confirm:$false
    Get-ChildItem -Path $localProfileTaskbar | Copy-Item -Destination U:\Laptop_Backup\Taskbar\Shortcuts\ -Recurse -Force
    Invoke-Command {Reg Export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband' U:\Laptop_Backup\Taskbar\Reg\Taskbar.reg}
}
    $progress.value = 60
#AVAYA SCRIPT
    

#local profile path...
Start-Job -ScriptBlock {
$loggedInUser = $env:UserName
$localProfile = "C:\Users\$($loggedInUser)\AppData\Roaming\Avaya"

#Copy Avaya profile contents...
   
    #create U drive profile path...
    New-Item -Path U:\Laptop_Backup\Avaya -ItemType Directory -Force -Confirm:$false

    #copy Local profile contents to U drive...
    Get-ChildItem -Path $localProfile | Copy-Item -Destination U:\Laptop_Backup\Avaya -Recurse -Force
 }
    $progress.value = 85
#Copy Outlook Profile...
Start-Job -ScriptBlock {
$loggedInUser = $env:UserName
    Invoke-Command  {reg export "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook" U:\Laptop_Backup\outlook.reg}
    New-Item -Path U:\Laptop_Backup\Outlook -ItemType Directory -Force -Confirm:$false
    Get-ChildItem -Path $localProfileSignature | Copy-Item -Destination U:\Laptop_Backup\Outlook -Recurse -Force
    
}
$progress.value = 100
    $StatusBackup.text =  "Complete!"
}

. InitializeComponent
$LaptopSetup.ShowDialog()