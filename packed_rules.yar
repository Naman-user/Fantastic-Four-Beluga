import "pe"

rule Ransomware_Detection {
    meta:
        description = "Detects common ransomware patterns"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $ransom_note2 = "All your files have been locked" nocase
        $ransom_note3 = "To recover your files, pay" nocase
        $ransom_ext1 = ".locked"
        $ransom_ext2 = ".enc"
        $ransom_ext3 = ".crypt"
        $ransom_ext4 = ".ransom"

    condition:
        any of ($ransom_note*) or any of ($ransom_ext*)
}

rule Trojan_Generic {
    meta:
        description = "Detects generic Trojan patterns"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $trojan1 = "cmd.exe /c powershell" nocase
        $trojan2 = "Get-Process | Out-File" nocase
        $trojan3 = "Invoke-WebRequest" nocase
        $trojan4 = "bypass UAC" nocase

    condition:
        any of them
}

rule Keylogger_Detection {
    meta:
        description = "Detects keyloggers based on known API calls"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $keylog1 = "GetAsyncKeyState" nocase
        $keylog2 = "SetWindowsHookExA" nocase
        $keylog3 = "RegisterRawInputDevices" nocase
        $keylog4 = "LogKeys" nocase

    condition:
        any of them
}

rule Stealer_Detection {
    meta:
        description = "Detects info stealers that extract sensitive data"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $stealer1 = "Saved Passwords" nocase
        $stealer2 = "Wallet.dat" nocase
        $stealer3 = "Browser History" nocase
        $stealer4 = "Clipboard Data" nocase

    condition:
        any of them
}

rule RAT_Detection {
    meta:
        description = "Detects Remote Access Trojans (RATs)"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $rat1 = "ReverseTCP" nocase
        $rat2 = "ngrok.io" nocase
        $rat3 = "No-IP" nocase
        $rat4 = "DynDNS" nocase
        $rat5 = "keylog feature enabled" nocase

    condition:
        any of them
}

rule Worm_Detection {
    meta:
        description = "Detects common self-replicating worms"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $worm1 = "Autorun.inf" nocase
        $worm2 = "copy %0 %temp%" nocase
        $worm3 = "Net Share" nocase
        $worm4 = "usb spread" nocase

    condition:
        any of them
}

rule Packed_KnownPackers {
    meta:
        description = "Detects known packers based on signatures"
        author = "Your Name"
        version = "1.1"
        date = "2025-02-23"

    strings:
        $upx = "UPX!"                     
        $asprotect = "ASProtect"          
        $themida = "Themida"              
        $mpress = "MPRESS"                
        $pecompact = "PECompact"          
        $execryptor = "ExeCryptor"        
        $armadillo = "Armadillo"
        $fsg = "FSG"                      
        $petite = "Petite" 
        $freearc = "FreeArc"       


    condition:
        any of them
}
