# Generated by binpac_quickstart

signature dpd_owamp {
	
	ip-proto == tcp

	# The initial server response will be exactly 64 bytes.
	payload-size == 64

	#  in practice the last byte is almost always \x07 (server allows all mode options, AEO)
	payload /^\x00{15}(\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07)/
	enable "owamp"
}