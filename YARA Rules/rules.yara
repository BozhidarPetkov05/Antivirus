rule trojan_check
{
    strings:
        $s0 = "VirtualProtect"
        $s1 = "VirtualAlloc"
        $s2 = "IsValidSid"
        $s3 = "Netbios"
        $s4 = "ShellExecute"
        $s5 = "URLDownloadToFile"
        $s6 = "FtpPutFile"
        $s7 = "send"
        $s8  = "WS2_32.dll"
        $s9  = "StartService"
        $s10 = "SetSecurityInfo"
        $s11 = "DeleteFile"
        $s12 = "FindFirstFile"
        $s13 = "FindNextFile"
        $s14 = "WriteFile"
        $s15 = "SearchPath"
        $s16 = "CreateDirectory"
        $s17 = "RemoveDirectory"
        $s18 = "CopyFile"
        $s19 = "CreateProcess"
        $s20 = "RegEnumKey"
        $s21 = "RegCreateKeyEx"
        $s22 = "RegDeleteValue"
        $s23 = "RegDeleteKey"
        $s24 = "RegCloseKey"
        $s25 = "RegEnumValue"
        $s26 = "RegOpenKey"
        $s27 = "WinExec"
        $s28 = "SetFileAttributes"
        $s29 = "MoveFileEx"

        $s30 = "GetProcAddress"
        $s31 = "LoadLibrary"
        $s32 = "WriteProcessMemory"
        $s33 = "CreateRemoteThread"
        $s34 = "OpenProcess"
        $s35 = "InternetOpenUrl"
        $s36 = "InternetReadFile"

        $exclude1 = "Inno Setup"
        $exclude2 = "NSIS"
        $exclude3 = "InstallShield"
        $exclude4 = "setup.exe"
        $exclude5 = "installer"
		
    condition:
        uint16(0) == 0x5A4D and
        none of ($exclude*) and
        (
            ((any of ($s0,$s1)) and (3 of ($s30,$s31,$s32,$s33,$s34)))
            or (6 of ($s*))
        )
}

rule adware_check
{
    strings:
        $a1 = "URLDownloadToFile"
        $a2 = "FtpPutFile"
        $a3 = "send"
        $a4 = "http://"
        $a5 = "ShellExecute"
        $a6 = "WinHttpOpen"
        $a7 = "InternetConnect"
        $a8 = "CreateProcess"
        $a9 = "WinHttpSendRequest"
        $a10 = "popup"
        $a11 = "advert"
        $a12 = "banner"
    condition:
        3 of ($a*)
}

rule ransomware_check
{
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "your files are encrypted" nocase
        $r3 = "recover" nocase
        $r4 = "restore" nocase
        $r5 = "bitcoin" nocase
        $r6 = "pay" nocase
        $r7 = "payment" nocase
        $r8 = "locked" nocase
        $r9 = "decrypt" nocase
        $r10 = "ransom" nocase
    condition:
        4 of ($r*)
}