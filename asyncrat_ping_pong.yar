rule asyncrat_rat_ping_pong
{
meta:
	description = "Regla YARA para detectar una variante de AsyncRAT"
	author = "Rita"
	date = "08-02-2022"
strings:
	$hexa1 = {53 00 74 00 75 00 62 00 2E 00 65 00 78 00 65}
	$hexa2 = {28 00 6E 00 65 00 76 00 65 00 72 00 20 00 75 00 73 00 65 00 64 00 29}

	$ascii1 = "CheckRemoteDebuggerPresent"
	$ascii2 = "GetTempFileName"
	$ascii3 = "set_UseShellExecute"
	$ascii4 = "KeepAlive"
	$ascii5 = "Hwid"
	$ascii6 = "DetectSandboxie"
	$ascii7 = "ActivatePong"
	$ascii8 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide //reversed
	$ascii9 = "vmware" wide
	$ascii10 = "VirtualBox" wide
	$ascii11 = "SbieDll" wide
	$ascii12 = "schtasks /create /f /sc" wide

condition:
	all of ($hexa*) and 10 of ($ascii*)
}