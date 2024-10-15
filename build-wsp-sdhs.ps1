param(
[Boolean]$signing=$true,
[string]$xerces_dir="xerces\windows"
)
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

if ($signing) {
  $SignTool = $ScriptDir + "\external\codesigning\bin\windows\x86\signtool.exe"
  $SignCert = "\\hobc03k.hob.de\disk_d\projects\Tools\certificate\MS_IE\cs-0619.pfx"

  $secure_password = read-host "Enter a Password for signing the files:" -asSecureString

  #hidden password is used
  $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure_password)
  $InsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

  function Sign-File
  {
   Param ($FileToSign)
   Process {
    $SignAlg = "sha256"
	$SignArgsSHA256 = @{
     FilePath = $SignTool
     ArgumentList = "sign", "/q", ("/f " + $SignCert), ("/fd " + $SignAlg), "/d", '"HOB Software"', ("/p " + $InsecurePassword),
        "/du", '"http://www.hobsoft.com"', "/tr", '"http://sha256timestamp.ws.symantec.com/sha256/timestamp"', $FileToSign
     Wait = $true
    }
    Start-Process @SignArgsSHA256 -NoNewWindow
   }
  }
}

if (-Not (Test-Path $xerces_dir)) {
Write-Host "No Xerces directory found. Please use, for example, files from D:\Xerces\xerces-c-3.1.0

especially

xerces\windows\include\xercesc is D:\Xerces\xerces-c-3.1.0\src\xercesc 
xerces\windows\lib64 is D:\Xerces\xerces-c-3.1.0\Build\windows\em64t\VC8\Release
xerces\windows\lib32 is D:\Xerces\xerces-c-3.1.0\Build\windows\x86\VC8\Release"
}

#change the header file number to the svn revision number of the actual svn header
#one could also revert this action with "svn revert $header_files"
function Change-Version-Number-SVN {
[regex]$regex_old_version = "(SDH_VERSION_4_NO | WS_VERSION_4_NO)\s+\d\d\d\d"
$header_files = dir src -recurse -include "*.h" | select-string -pattern $regex_old_version  | Get-ChildItem
$svn_version = svn info | where { $_ -match "Revision: "} | %{$_.split(": ")[2]}

  foreach ($file in $header_files)
    {
     (Get-Content $file.PSPath) |
     Foreach-Object { $_ -replace "\d\d\d\d", $svn_version } |
     Set-Content $file.PSPath
    }
}

if (svn info) {
 Change-Version-Number-SVN
}

cd "$ScriptDir\src\wsp"
.\DO-GEN-RC-IBIPGW08.bat
cd $ScriptDir

# Local Build Variables
$MsBuild = $env:systemroot + "\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe";
$SourceCodePath = "$ScriptDir\src\wsp\";
$SolutionFile = "ibipgw08.sln";
$SlnFilePath = $SourceCodePath + $SolutionFile; 
$BuildLog = "$ScriptDir\src\build_ibipgw.win.log";
$stdErrLog = "$ScriptDir\src\stderr.log"
$stdOutLog = "$ScriptDir\src\stdout.log"
Clear-Host

Write-Host "Please make sure you do not have any instances of Visual studio running before running the script..." `
        -ForegroundColor Red -BackgroundColor White

Write-Host "#Build: build, sign and copy ibipgw08.exe"
$Configuration = "Release";
$Platform = @("x64", "Win32");

$xerces_abs = (resolve-path $xerces_dir).Path;
Write-Host "#Build: looking for Xerces in $xerces_abs"
$XercesInclude = ($xerces_abs + "\include");
$XercesLibs = @(($xerces_abs + "\lib64\xerces-c_3.lib"), ($xerces_abs + "\lib32\xerces-c_3.lib"));
for ($j=0; $j -lt $Platform.Count; $j++) {
#/t target
#You can specify the following verbosity levels in MSBuild: q[uiet], m[inimal], n[ormal], d[etailed], and diag[nostic].
$BuildArgs = @{
 FilePath = $MsBuild
 ArgumentList = $SlnFilePath, "/t:build", ("/property:Configuration=" + $Configuration), "/fileLogger",
                    ("/property:Platform=" + $Platform[$j]), "/verbosity:minimal", "/m", ("/p:BuildInParallel=" + $true),
                    ("/property:additional_includes=" + $XercesInclude),
                    ("/property:additional_libs=" + $XercesLibs[$j])
 RedirectStandardOutput = $stdOutLog
 RedirectStandardError = $stdErrLog
 Wait = $true
 }
 Write-Host "Building $SolutionFile for $($Platform[$j])."
 $proc = Start-Process @BuildArgs -NoNewWindow -PassThru
 $handle = $proc.Handle # cache proc.Handle http://stackoverflow.com/a/23797762/1479211
 if($proc.ExitCode -ne 0) { Write-Host "#Build: Building $SolutionFile for $($Platform[$j]) failed"; exit 1; } `
 else { Write-Host "#Build: Building $SolutionFile for $($Platform[$j]) succeeded" }
 Get-Content $stdErrLog, $stdOutLog | Out-File $BuildLog -Append
} 

if ($signing) {
 Sign-File "$ScriptDir\src\wsp\ibipgw08-r-x86\ibipgw08.exe" 
 Sign-File "$ScriptDir\src\wsp\ibipgw08-r-EM64T\ibipgw08.exe"
}
Copy-Item "$ScriptDir\src\wsp\ibipgw08-r-x86\ibipgw08.exe" ..\binaries\wsp.win_x86\ 
Copy-Item "$ScriptDir\src\wsp\ibipgw08-r-EM64T\ibipgw08.exe" ..\binaries\wsp.win_em64t\

Write-Host "#Build: build, sign, copy SDHs"
cd "$ScriptDir\src"
& .\build-win.ps1 -NUMBER_OF_PROCESSORS $env:NUMBER_OF_PROCESSORS -xerces_include $XercesInclude
 if($?) { Write-Host "#Build: Building SDHs succeeded" } `
 else { Write-Host "#Build: Building SDHs failed with code $LastExitCode"; exit 1 }
cd ..

$arch = @("em64t", "x86")
for ($j=0; $j -lt $arch.Count; $j++) {
    $libPath = "$ScriptDir\bin\release\windows\" + $arch[$j] + "\plugins"
    $target = "$ScriptDir\..\binaries\wsp.win_" + $arch[$j]
	if(!(Test-Path -Path $libPath )){
		New-Item -ItemType directory -Path $libPath
	}
    $files = Get-ChildItem -path $libPath -recurse -include *.dll,*.manifest
    for ($i=0; $i -lt $files.Count; $i++) {
        # sign before copying
        if ($files[$i].extension -eq ".dll"){
          if ($signing) { Sign-File $files[$i].FullName }
        }
        $dirDest = $target + "\plugins\" + $files[$i].Directory.Name
        if (-Not (Test-Path $dirDest)){$dirDest = (Get-ChildItem ($dirDest + ".*")).FullName}
        Copy-item -path $files[$i].FullName -destination $dirDest
        Write-Host $files[$i].FullName " copied to " $dirDest
    }
}
# SIG # Begin signature block
# MIIbrAYJKoZIhvcNAQcCoIIbnTCCG5kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCRWkc6MzyevT8C
# VYxl3Dc7wTN53evVfg9R982kincAg6CCCl4wggT9MIID5aADAgECAhBZhQi7tYqz
# 1O1izDrs/nPdMA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQK
# ExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3Qg
# TmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBT
# aWduaW5nIENBMB4XDTE3MDYyMTAwMDAwMFoXDTE5MDYyMzIzNTk1OVowgZQxCzAJ
# BgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRMwEQYDVQQHDApDYWRvbHpidXJn
# MRowGAYDVQQKDBFIT0IgR21iSCAmIENvLiBLRzEmMCQGA1UECwwdU2VjdXJpdHkg
# U29mdHdhcmUgRGV2ZWxvcG1lbnQxGjAYBgNVBAMMEUhPQiBHbWJIICYgQ28uIEtH
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAugWtMx5IVfkdfxPsjHV8
# YQSAoGqQZ0y+I441qckf3N3vvKcUBnogEUHNaz764MRnxeUlylGEiRE/TkLq7Yfk
# +fdR/v5Ap/uZMDi6ltobOjjJHVuT/5rF0Cnk5s8Nghh2oY5ciwS3S5yQMwUzVZSA
# lk0/3t4DGvZFM9F0bgz3YbZf90GPjKe2cIRXBmH3tacfrimUj4aV6NGBjg4Y9MRU
# zxkUJFT06RA31L1WqbZxxJywIXE2IPT9I88g3GOTbOOhaZ7GlYqJtXTbSVbtUW7V
# OLe2AQmvtDh3bj9qjH7EqD5r/WYL/4k2gDOsvQnl6mJ1BKaHnhpHQc7G6hGecaPv
# vwIDAQABo4IBXTCCAVkwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0f
# BCQwIjAgoB6gHIYaaHR0cDovL3N2LnN5bWNiLmNvbS9zdi5jcmwwYQYDVR0gBFow
# WDBWBgZngQwBBAEwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9j
# cHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRw
# Oi8vc3Yuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8vc3Yuc3ltY2IuY29t
# L3N2LmNydDAfBgNVHSMEGDAWgBSWO1PweTOXr32D7y4rzMq3hh5yZjAdBgNVHQ4E
# FgQU+ov69nJkvlEvjJApxodxOxWcaZIwDQYJKoZIhvcNAQELBQADggEBADsA/wo3
# IANUCtzTZa4Id3EeAuzZJfHHaxNAPJNGcp90WEfVFBc3TulaM2pMvRNLGj6qbCve
# 5LGuj4e0mnloM/KGlebMWBNU2cK7oU9vkXAG+j6GUSlrDhh96N8YB6oB1runSsU2
# 9o5Y1m12p8zBkzG/RB7kRWZdj5Ohia6fDQMC8ZZYTNltsBLZCabTZHc7yse3KT5j
# YH2M+YCO5usdR389/RBYw89qrsxCOSn4sDSIre+t+YMOTgiwd48XPANmhZlXN5qu
# SIZn0NRJmId5pSVIiu2qm4vQkCeSimbOShGhP8HPHvU2Zpknj1rqNEqvPxzRNm0S
# FWuKiF7l0V0c2mYwggVZMIIEQaADAgECAhA9eNf5dklgsmF99PAeyoYqMA0GCSqG
# SIb3DQEBCwUAMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIElu
# Yy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShj
# KSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkx
# RTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlm
# aWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0xMzEyMTAwMDAwMDBaFw0yMzEyMDky
# MzU5NTlaMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMn
# U3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl4MeABavLLHSCMTXaJNRYB5x9uJHtNtY
# TSNiarS/WhtR96MNGHdou9g2qy8hUNqe8+dfJ04LwpfICXCTqdpcDU6kDZGgtOwU
# zpFyVC7Oo9tE6VIbP0E8ykrkqsDoOatTzCHQzM9/m+bCzFhqghXuPTbPHMWXBySO
# 8Xu+MS09bty1mUKfS2GVXxxw7hd924vlYYl4x2gbrxF4GpiuxFVHU9mzMtahDkZA
# xZeSitFTp5lbhTVX0+qTYmEgCscwdyQRTWKDtrp7aIIx7mXK3/nVjbI13Iwrb2py
# XGCEnPIMlF7AVlIASMzT+KV93i/XE+Q4qITVRrgThsIbnepaON2b2wIDAQABo4IB
# gzCCAX8wLwYIKwYBBQUHAQEEIzAhMB8GCCsGAQUFBzABhhNodHRwOi8vczIuc3lt
# Y2IuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwbAYDVR0gBGUwYzBhBgtghkgBhvhF
# AQcXAzBSMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1dGguY29tL2NwczAo
# BggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5bWF1dGguY29tL3JwYTAwBgNVHR8E
# KTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2IuY29tL3BjYTMtZzUuY3JsMB0GA1Ud
# JQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCAQYwKQYDVR0R
# BCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJLTEtNTY3MB0GA1UdDgQWBBSW
# O1PweTOXr32D7y4rzMq3hh5yZjAfBgNVHSMEGDAWgBR/02Wnwt3su/AwCfNDOfoC
# rzMxMzANBgkqhkiG9w0BAQsFAAOCAQEAE4UaHmmpN/egvaSvfh1hU/6djF4MpnUe
# eBcj3f3sGgNVOftxlcdlWqeOMNJEWmHbcG/aIQXCLnO6SfHRk/5dyc1eA+CJnj90
# Htf3OIup1s+7NS8zWKiSVtHITTuC5nmEFvwosLFH8x2iPu6H2aZ/pFalP62ELine
# fLyoqqM9BAHqupOiDlAiKRdMh+Q6EV/WpCWJmwVrL7TJAUwnewusGQUioGAVP9rJ
# +01Mj/tyZ3f9J5THujUOiEn+jf0or0oSvQ2zlwXeRAwV+jYrA9zBUAHxoRFdFOXi
# vSdLVL4rhF4PpsN0BQrvl8OJIrEfd/O9zUPU8UypP7WLhK9k8tAUITGCEKQwghCg
# AgEBMIGTMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMn
# U3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBAhBZhQi7tYqz
# 1O1izDrs/nPdMA0GCWCGSAFlAwQCAQUAoIGyMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJ
# BDEiBCBkL94sk4qf6ej/V3ylGY9C67yCfGz4Hej0HfLiZF+OMzBGBgorBgEEAYI3
# AgEMMTgwNqAagBgASABPAEIAIABTAG8AZgB0AHcAYQByAGWhGIAWaHR0cDovL3d3
# dy5ob2Jzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQBpvdCSlH3OhRrrMw04GLHb
# IKeWOpmNvaPQ6KrkSfLC3YHe3G/jjuem6vF8E/EzswwAHfCKXq2HOk4OhHY6FAuU
# gl9LXCdJDVkZKR6NxHKEBS3QRLRmKSwYkgmU8XkseKJ7K+gYLqyZfg/q2skOy/Q1
# HmYLfhxcUuiCSCVhb40Jw9drGckKltNHPuFaG5RgTDWlGpkznt5++UNU0AMHYuP4
# a/rdRNsymgjcJMe3kdZ/wzXZk3fruu4dpIb1YWqpFU1Q/0hdWoB1uVRqvNg/PAAi
# KFdDzrtUDJhjsDi1XXf1MXMMrRBMsOUL7E3Ihm46fxOOGEPEPtelqlr2gTmGfLsU
# oYIOLDCCDigGCisGAQQBgjcDAwExgg4YMIIOFAYJKoZIhvcNAQcCoIIOBTCCDgEC
# AQMxDTALBglghkgBZQMEAgEwgf8GCyqGSIb3DQEJEAEEoIHvBIHsMIHpAgEBBgtg
# hkgBhvhFAQcXAzAhMAkGBSsOAwIaBQAEFEj8dsoRpy6KlYntCvdlw43moA9nAhUA
# xUSVLUx5OHEI2SpkH4UJWYCbKJ0YDzIwMTgwNTE1MTI1MjE5WjADAgEeoIGGpIGD
# MIGAMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24x
# HzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFu
# dGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzKgggqLMIIFODCCBCCg
# AwIBAgIQewWx1EloUUT3yYnSnBmdEjANBgkqhkiG9w0BAQsFADCBvTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2ln
# biBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5j
# LiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBV
# bml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAxMTIw
# MDAwMDBaFw0zMTAxMTEyMzU5NTlaMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRT
# eW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0
# d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtZnVlVT52Mcl0agaLrVfOw
# Aa08cawyjwVrhponADKXak3JZBRLKbvC2Sm5Luxjs+HPPwtWkPhiG37rpgfi3n9e
# bUA41JEG50F8eRzLy60bv9iVkfPw7mz4rZY5Ln/BJ7h4OcWEpe3tr4eOzo3HberS
# mLU6Hx45ncP0mqj0hOHE0XxxxgYptD/kgw0mw3sIPk35CrczSf/KO9T1sptL4YiZ
# GvXA6TMU1t/HgNuR7v68kldyd/TNqMz+CfWTN76ViGrF3PSxS9TO6AmRX7WEeTWK
# eKwZMo8jwTJBG1kOqT6xzPnWK++32OTVHW0ROpL2k8mc40juu1MO1DaXhnjFoTcC
# AwEAAaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEA
# MGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNi
# LmNvbS9ycGEwLgYIKwYBBQUHAQEEIjAgMB4GCCsGAQUFBzABhhJodHRwOi8vcy5z
# eW1jZC5jb20wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3Muc3ltY2IuY29tL3Vu
# aXZlcnNhbC1yb290LmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAoBgNVHREEITAf
# pB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMzAdBgNVHQ4EFgQUr2PWyqNO
# hXLgp7xB8ymiOH+AdWIwHwYDVR0jBBgwFoAUtnf6aUhHn1MS1cLqBzJ2B9GXBxkw
# DQYJKoZIhvcNAQELBQADggEBAHXqsC3VNBlcMkX+DuHUT6Z4wW/X6t3cT/OhyIGI
# 96ePFeZAKa3mXfSi2VZkhHEwKt0eYRdmIFYGmBmNXXHy+Je8Cf0ckUfJ4uiNA/vM
# kC/WCmxOM+zWtJPITJBjSDlAIcTd1m6JmDy1mJfoqQa3CcmPU1dBkC/hHk1O3MoQ
# eGxCbvC2xfhhXFL1TvZrjfdKer7zzf0D19n2A6gP41P3CnXsxnUuqmaFBJm3+AZX
# 4cYO9uiv2uybGB+queM6AL/OipTLAduexzi7D1Kr0eOUA2AKTaD+J20UMvw/l0Dh
# v5mJ2+Q5FL3a5NPD6itas5VYVQR9x5rsIwONhSrS/66pYYEwggVLMIIEM6ADAgEC
# AhBUWPKq10HWRLyEqXugllLmMA0GCSqGSIb3DQEBCwUAMHcxCzAJBgNVBAYTAlVT
# MR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50
# ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQTAeFw0xNzAxMDIwMDAwMDBaFw0yODA0MDEyMzU5NTlaMIGAMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
# BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNI
# QTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCZ8/zYBAkDhvnXXKaTwEJ86nxjz10A4o7zwJDfjyn1GOqU
# t5Ll17Cgc4Ho6QqbSnwB/52PpDmnDupF9CIMOnDtOUWL5MUbXPBFaEYkBWN2mxz8
# nmwqsVblin9Sca7yNdVGIwYcz0gtHbTNuNl2I44c/z6/uwZcaQemZQ74Xq59Lu1N
# rjXvydcAQv0olQ6fXXJCCbzD2kTS7cxHhOT8yi2sWL6u967ZRA0It8J31hpDcNFu
# A95SksQQCHHZuiJV8h+87ZudO+JeHUyD/5cPewvnVYNO0g3rvtfsrm5HuZ/fpdZR
# vARV7f8ncEzJ7SpLE+GxuUwPyQHuVWVfaQJ4Zss/AgMBAAGjggHHMIIBwzAMBgNV
# HRMBAf8EAjAAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cDovL3RzLWNy
# bC53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jcmwwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMHcGCCsGAQUFBwEBBGswaTAqBggr
# BgEFBQcwAYYeaHR0cDovL3RzLW9jc3Aud3Muc3ltYW50ZWMuY29tMDsGCCsGAQUF
# BzAChi9odHRwOi8vdHMtYWlhLndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNh
# LmNlcjAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtNTAd
# BgNVHQ4EFgQUCbXB/pZylylDmsngArqu+P0vuvYwHwYDVR0jBBgwFoAUr2PWyqNO
# hXLgp7xB8ymiOH+AdWIwDQYJKoZIhvcNAQELBQADggEBABezCojpXFpeIGs7ChWy
# bMWpijKH07H0HFOuhb4/m//XvLeUhbTHUn6U6L3tYbLUp5nkw8mTwTU9C+hoCl1W
# mL2xIjvRRHrXv/BtUTKK1SPfOAE39uJTK3orEY+3TWx6MwMbfGsJlBe75NtY1CET
# Zefs0SXKLHWanH/8ybsqaKvEfbTPo8lsp9nEAJyJCneR9E2i+zE7hm725h9QA4ab
# v8tCq+Z2m3JaEQGKxu+lb5Xn3a665iJl8BhZGxHJzYC32JdHH0II+KxxH7BGU7PU
# stWjq1B1SBIXgq3P4EFPMn7NlRy/kYoIPaSnZwKW3yRMpdBBwIJgo4oXMkvTvM+k
# tIwxggJaMIICVgIBATCBizB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsx
# KDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEFRY8qrX
# QdZEvISpe6CWUuYwCwYJYIZIAWUDBAIBoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTgwNTE1MTI1MjE5WjAvBgkqhkiG9w0B
# CQQxIgQgpCEXHmM68H2UuslZMUWxxhvoXMNTTsNQX/7Pk9j0XM4wNwYLKoZIhvcN
# AQkQAi8xKDAmMCQwIgQgz3rBetBH7NX9w2giAxsS1O8Hi28rTF5rpB+P8s9LrWcw
# CwYJKoZIhvcNAQEBBIIBAC8LwgY7OPMooV9xtyv7p0269ZAqwrSpbZm3W+E8WEcg
# pN4B3RFPUTmc+JMuSfrJZVK7xxZ193+iAOeBQCOZ3aOwwB7tsreXEdC1T3uovn3M
# G0y1sKeGZgjtT0CSGi7lHECYOu+6vOWBIkNbnDC68wHANutIC4vjeX9DKAJiY6Rs
# Qo36efULnuAhZsVDR6YER6lK5eAkXpUtWFUO7OY2hxg4frYOMeuPtiBlCL6Vp3KV
# KjF5Tn0kCFBnjiHDVU23iVwdSUEt/hNgJTT8GzuKVaGmWccdtBN08zDSBLa6w2XK
# EEfGnTzP0sZmLBeA8+b0pVzgsAkJd6vlMjZcbaUvgs8=
# SIG # End signature block
