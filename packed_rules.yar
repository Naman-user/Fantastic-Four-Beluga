import "pe"

rule Packed_KnownPackers {
    meta:
        description = "Detects known packers based on signatures"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    strings:
        $upx = "UPX!"                     
        $asprotect = "ASProtect"          
        $themida = "Themida"              
        $mpress = "MPRESS"                
        $pecompact = "PECompact"          
        $execryptor = "ExeCryptor"        

    condition:
        any of ($upx, $asprotect, $themida, $mpress, $pecompact, $execryptor)
}

rule Packed_HighEntropy {
    meta:
        description = "Detects packed files using high entropy in PE sections"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    condition:
        for any section in pe.sections : (section.entropy > 7.0)
}

rule Packed_SuspiciousSections {
    meta:
        description = "Detects packed files based on unusual PE section names"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    condition:
        for any section in pe.sections : (
            section.name == ".upx0" or section.name == ".upx1" or
            section.name == ".packed" or section.name == ".data0" or
            section.name == ".text0" or section.name == ".wprotect"
        )
}

rule Packed_EntryPointCheck {
    meta:
        description = "Detects packed files where entry point is outside .text section"
        author = "Your Name"
        version = "1.0"
        date = "2025-02-23"

    condition:
        pe.entry_point != pe.sections[0].raw_address
}
