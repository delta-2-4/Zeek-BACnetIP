# Generated by binpac_quickstart

signature dpd_bacnet {
	

	ip-proto == udp

	payload /\x81/

	enable "bacnet"
}