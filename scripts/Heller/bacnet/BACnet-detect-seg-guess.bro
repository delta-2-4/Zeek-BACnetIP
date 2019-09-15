##! BACnet/IP segmeneted message sequence number attack detector,
##! triggering when there are more than two devices using the same
##! Invoke ID.

@load base/frameworks/notice/weird
@load base/frameworks/sumstats
@load base/utils/time

module bacnet;

export {
    redef enum Notice::Type += {
        ## Indicates a host guessing segmeneted message sequnces by 
        ## watching for more than two hosts using the same Invoke ID.
        Sequence_Guessing
    };

    ### The time period in which the threshold needs to be crossed before
    ### being reset.
    const guessing_measurement_interval = 5mins &redef;
}


event bro_init()
	{
	#Reduce the set of observations to unique values
	local r1  = SumStats::Reducer($stream="bacnet.Sequence_Guessing", $apply=set(SumStats::UNIQUE));

	#Generates a notice in the notice log if there is more than one endpoint attempting to respond to a segmented request
	SumStats::create([$name="bacnet-detect-sequence-guessing",
                      $epoch=guessing_measurement_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["bacnet.Sequence_Guessing"]$unique+0.0;
                          },
                      $threshold=2.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local r = result["bacnet.Sequence_Guessing"];
                          local message = fmt("%d endpoints tried to participate in a 2 endpoint conversation with %s", r$unique, key$str);
                          NOTICE([$note=bacnet::Sequence_Guessing,
                                  $msg=message,
                                  $identifier=cat(key$str)]);
                          }]);



    }

event bacnet_ethernet_NPDU(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::NPDUs, NET : count, LEN : count, ADR : string, Hop_Count : count, APDU : string)
    {
	#Grabs the first byte of the APDU so it can be more easily manipulated
	local APDU_first: count = bytestring_to_count(APDU[0:1]);

	#Extracts the APDU type from the first byte of the APUD, as a number
	#APDU type is determined by the highest 4 bits of the first APDU byte
	local APDU_Type	: count = ( APDU_first / 16 );
	print fmt("NPDU------------------> In detection script! NPDU$Control = %x | APDU 1st byte = %x", NPDU$Control, APDU_first);
	#Determines if the APDU type is segmented and could be affected by sequence number guessing
	if ((NPDU$Control & 0x80 == 0x00) && (APDU_first & 0x0A >= 0x00))
		{
		switch APDU_Type
			{
				#Confirmed Request APDUs with segmenetaiton initiate the Original Invoke ID, which
				#is used in combination with the origin device address to track
				#which APDUs are additional segments in the connection.  Since the origin device may
				#be Ethernet/IP based, the NETwork number and ADdRess of the device is also captured
				#so we can track instance of the same Invoke IDs coming from the IP address of a
				#non-Etherent/IP network to Ethernet/IP network router.
				case 0x0:
					SumStats::observe("bacnet.Sequence_Guessing", SumStats::Key($str=fmt("%s:%d|%d", c$id$orig_h, c$id$orig_p,bytestring_to_count(APDU[2:3]))), SumStats::Observation($str=fmt("%s:%d|%d|%s", c$id$resp_h, c$id$resp_p, NET, ADR)));
					print fmt("Request: %s:%d|%d --> Observation: %s:%d|%d|%s", c$id$orig_h, c$id$orig_p,bytestring_to_count(APDU[2:3]),c$id$resp_h, c$id$resp_p, NET, ADR);
					break;

				#Complex ACK and Segmeneted ACK APDUs include the Invoke ID established by the
				#requesting node in combination with the origin device address to track
				#which APDUs are additional segments in the connection.
				case 0x3, 0x4:
					SumStats::observe("bacnet.Sequence_Guessing", SumStats::Key($str=fmt("%s:%d|%d", c$id$resp_h, c$id$resp_p,bytestring_to_count(APDU[1:2]))), SumStats::Observation($str=fmt("%s:%d|%d|%s", c$id$orig_h, c$id$orig_p, NET, ADR)));
					print fmt("ACK Key: %s:%d|%d --> Observation: %s:%d|%d|%s", c$id$resp_h, c$id$resp_p,bytestring_to_count(APDU[1:2]),c$id$orig_h, c$id$orig_p, NET, ADR);

					break;
			}
		}
    }

event bacnet_ethernet_NPDU_No(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::MiniNPDUs, NET : count, LEN : count, ADR : string, Hop_Count : count, APDU : string)
    {
	#Grabs the first byte of the APDU so it can be more easily manipulated
	local APDU_first: count = bytestring_to_count(APDU[0:1]);

	#Extracts the APDU type from the first byte of the APUD, as a number
	#APDU type is determined by the highest 4 bits of the first APDU byte
	local APDU_Type	: count = ( APDU_first / 16 );
	print fmt("NPDU$Control = %x | APDU 1st byte = %x | APDU Type = %x", NPDU$Control, APDU_first, APDU_Type);
	#Determines if the APDU type is segmented and could be affected by sequence number guessing
	if ((NPDU$Control & 0x80 == 0x00) && (APDU_first & 0x0A >= 0x00))
		{
		switch APDU_Type
			{
				#Confirmed Request APDUs with segmenetaiton initiate the Original Invoke ID, which
				#is used in combination with the origin device address to track
				#which APDUs are additional segments in the connection.  Since the origin device may
				#be Ethernet/IP based, the NETwork number and ADdRess of the device is also captured
				#so we can track instance of the same Invoke IDs coming from the IP address of a
				#non-Etherent/IP network to Ethernet/IP network router.
				case 0x0:
					SumStats::observe("bacnet.Sequence_Guessing", SumStats::Key($str=fmt("%s:%d|%d", c$id$orig_h, c$id$orig_p,bytestring_to_count(APDU[2:3]))), SumStats::Observation($str=fmt("%s:%d|%d|%s", c$id$resp_h, c$id$resp_p, NET, ADR)));
					print fmt("Request: %s:%d|%d --> Observation: %s:%d|%d|%s", c$id$orig_h, c$id$orig_p,bytestring_to_count(APDU[2:3]),c$id$resp_h, c$id$resp_p, NET, ADR);
					break;

				#Complex ACK and Segmeneted ACK APDUs include the Invoke ID established by the
				#requesting node in combination with the origin device address to track
				#which APDUs are additional segments in the connection.
				case 0x3, 0x4:
					SumStats::observe("bacnet.Sequence_Guessing", SumStats::Key($str=fmt("%s:%d|%d", c$id$resp_h, c$id$resp_p,bytestring_to_count(APDU[1:2]))), SumStats::Observation($str=fmt("%s:%d|%d|%s", c$id$orig_h, c$id$orig_p, NET, ADR)));
					print fmt("ACK Key: %s:%d|%d --> Observation: %s:%d|%d|%s", c$id$resp_h, c$id$resp_p,bytestring_to_count(APDU[1:2]),c$id$orig_h, c$id$orig_p, NET, ADR);

					break;
			}
		}
    }

event bacnet_ethernet_NPDU_SD_No(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::MiniNPDUs, SNET : count, SLEN : count, NET : count, LEN : count, SADR : string, ADR : string, Hop_Count : count, APDU : string)
    {
	#Grabs the first byte of the APDU so it can be more easily manipulated
	local APDU_first: count = bytestring_to_count(APDU[0:1]);

	#Extracts the APDU type from the first byte of the APUD, as a number
	#APDU type is determined by the highest 4 bits of the first APDU byte
	local APDU_Type	: count = ( APDU_first / 16 );
	print fmt("NPDU_SD_No------------> In detection script! NPDU$Control = %x | APDU 1st byte = %x", NPDU$Control, APDU_first);
	#Determines if the APDU type is segmented and could be affected by sequence number guessing
	if ((NPDU$Control & 0x80 == 0x00) && (APDU_first & 0x0A >= 0x00))
		{
		switch APDU_Type
			{
				#Confirmed Request APDUs with segmenetaiton initiate the Original Invoke ID, which
				#is used in combination with the origin device address to track
				#which APDUs are additional segments in the connection.  Since the origin device may
				#be Ethernet/IP based, the NETwork number and ADdRess of the device is also captured
				#so we can track instance of the same Invoke IDs coming from the IP address of a
				#non-Etherent/IP network to Ethernet/IP network router.
				case 0x0:
					SumStats::observe("bacnet.Sequence_Guessing", SumStats::Key($str=fmt("%s:%d|%d", c$id$orig_h, c$id$orig_p,bytestring_to_count(APDU[2:3]))), SumStats::Observation($str=fmt("%s:%d|%d|%s", c$id$resp_h, c$id$resp_p, NET, ADR)));
					print fmt("Request: %s:%d|%d --> Observation: %s:%d|%d|%s", c$id$orig_h, c$id$orig_p,bytestring_to_count(APDU[2:3]),c$id$resp_h, c$id$resp_p, NET, ADR);
					break;

				#Complex ACK and Segmeneted ACK APDUs include the Invoke ID established by the
				#requesting node in combination with the origin device address to track
				#which APDUs are additional segments in the connection.
				case 0x3, 0x4:
					SumStats::observe("bacnet.Sequence_Guessing", SumStats::Key($str=fmt("%s:%d|%d", c$id$resp_h, c$id$resp_p,bytestring_to_count(APDU[1:2]))), SumStats::Observation($str=fmt("%s:%d|%d|%s", c$id$orig_h, c$id$orig_p, NET, ADR)));
					print fmt("ACK Key: %s:%d|%d --> Observation: %s:%d|%d|%s", c$id$resp_h, c$id$resp_p,bytestring_to_count(APDU[1:2]),c$id$orig_h, c$id$orig_p, NET, ADR);

					break;
			}
		}
    }