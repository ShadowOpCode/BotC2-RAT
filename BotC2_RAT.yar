import "pe"

rule BOTCFG_Native_RAT_Code_Cluster
{
    meta:
        description = "Native x64 RAT code cluster; descriptive label, not attributed family"
        date = "2026-09-20"
        sample_sha256 = "a5926522d7ce3a0073da79c5082da6644c742d6a34440bba3f5d878f03712938"
	author = "ShadowOpCode"
    strings:
        $marker = "BOTCFG|" ascii
        $mutex = "Local\\BotC2Stub.SingleInstance" wide
        $c1 = "CLIPPER_CONFIG" ascii fullword
        $c2 = "CRYPTO_FOUND" ascii fullword
        $c3 = "SCREENCAST_START" ascii fullword
        $c4 = "TERMINAL_INPUT" ascii fullword
        $c5 = "PERSISTENCE_INSTALL" ascii fullword
        $c6 = "hollowed pid " ascii
    condition:
        uint16(0) == 0x5a4d and pe.machine == pe.MACHINE_AMD64 and
        filesize < 5MB and $marker and $mutex and 4 of ($c*)
}

rule BOTCFG_DGM_Embedded_Config_20260920
{
    meta:
        description = "Sample configuration, independent of filename and hash"
        date = "2026-09-20"
		author = "ShadowOpCode"
    strings:
        $config = "BOTCFG|host=axwtexa.ddns.net|fallback=back001xtc.ddns.net|port=8080|tag=DGM|name=Runtimebroker|persist=reg|" ascii
    condition:
        uint16(0) == 0x5a4d and pe.machine == pe.MACHINE_AMD64 and $config
}
