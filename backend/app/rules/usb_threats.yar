// AEGIS USB detection rules. Compiled once. Externals: filename, extension (lower-case, no dot).
// Rules match inert indicators only.

rule Autorun_Inf_Abuse
{
    meta:
        description = "autorun.inf that launches a program (USB worm technique)"
        mitre = "T1091"
    strings:
        $hdr  = "[autorun]" nocase
        $open = /open\s*=/ nocase
        $se   = /shellexecute\s*=/ nocase
        $sh   = /shell\\[^\r\n]*\\command\s*=/ nocase
    condition:
        $hdr and ($open or $se or $sh)
}

rule Suspicious_PowerShell_Dropper
{
    meta:
        description = "PowerShell download-and-execute or encoded command"
        mitre = "T1059.001"
    strings:
        $iex  = /(^|[^A-Za-z])IEX[ \t(]/ nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1  = "DownloadString" nocase
        $dl2  = "DownloadFile" nocase
        $enc  = /-enc(odedcommand)?[ \t]+[A-Za-z0-9+\/=]{20,}/ nocase
    condition:
        (($iex or $iex2) and ($dl1 or $dl2)) or $enc
}

rule Magic_Spoof_Executable
{
    meta:
        description = "Executable header disguised with a benign extension"
        mitre = "T1036.008"
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F)
        and extension matches /^(pdf|docx|xlsx|pptx|jpg|jpeg|png|gif|txt|csv|mp3|mp4)$/
}

rule UPX_Packed_Executable
{
    meta:
        description = "PE with UPX section names"
        mitre = "T1027.002"
    strings:
        $u0 = "UPX0"
        $u1 = "UPX1"
    condition:
        uint16(0) == 0x5A4D and $u0 and $u1
}

rule Ransomware_Shadow_Delete
{
    meta:
        description = "Shadow copy deletion / recovery disabling commands"
        mitre = "T1490"
    strings:
        $vss = /vssadmin(\.exe)?[ \t]+delete[ \t]+shadows/ nocase
        $bcd = /bcdedit[^\r\n]{0,60}recoveryenabled[ \t]+no/ nocase
    condition:
        any of them
}

rule Demo_EICAR_Signature
{
    meta:
        description = "Harmless AEGIS demo signature (not real malware)"
        mitre = "T1204.002"
    strings:
        $sig = "AEGIS-TEST-MALWARE-SIGNATURE-2026"
    condition:
        $sig
}
