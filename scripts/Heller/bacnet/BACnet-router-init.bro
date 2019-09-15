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
        Router_Init
    };

    ### The time period in which the threshold needs to be crossed before
    ### being reset.
    const measurement_interval = 5sec &redef;
}

global minitracker: function(c: connection, NPDU : bacnet::MiniNPDUs, APDU : string): count;
global tracker: function(c: connection, NPDU : bacnet::NPDUs, APDU : string): count;

event bro_init()
	{
	#Reduce the set of observations to count the number of entries values
	local r1  = SumStats::Reducer($stream="bacnet.Router_Init", $apply=set(SumStats::UNIQUE));

	#Generates a notice in the notice log when Intitialize-Routing-Table messages occur or they
	#sucessfully update or return the contents of a routing table

	SumStats::create([$name="bacnet-router-intialize-table",
                      $epoch=measurement_interval,
                      $reducers=set(r1),
		      $threshold = 1.5,
		      $threshold_val(key: SumStats::Key, result: SumStats::Result) = 
			{
				return result["bacnet.Router_Init"]$unique+0.0;
			},
		      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
			{
                          local r = result["bacnet.Router_Init"];
                          local message = fmt("Threshold crossed - %s | Begin: %s | End: %s | Num: %d | Sum: %f | Unique: %d",key$str, r$begin, r$end, r$num, r$sum, r$unique);
				print message;
			},
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                          {
                          	local r = result["bacnet.Router_Init"];
                          	local message = fmt("Epoch Timeout - %s | Begin: %s | End: %s | Num: %d | Sum: %f | Unique: %d",key$str, r$begin, r$end, r$num, r$sum, r$unique);
				print message;
                          	NOTICE([$note=bacnet::Router_Init,
                                 $msg=message,
                                  $identifier=cat(key$str)]);
                          }
			]);



    }

#############################################################################################
# ####### This section has the events which could contain an Initialize-Routing-Table or Initialize-Routing-Table-ACK message
#############################################################################################
event bacnet_ethernet_NPDU(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::NPDUs, NET : count, LEN : count, ADR : string, Hop_Count : count, APDU : string)
    {
	tracker(c, NPDU, APDU);
    }

event bacnet_ethernet_NPDU_No(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::MiniNPDUs, NET : count, LEN : count, ADR : string, Hop_Count : count, APDU : string)
    {
	minitracker(c, NPDU, APDU);
    }

event bacnet_ethernet_NPDU_SD_No(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::MiniNPDUs, SNET : count, SLEN : count, NET : count, LEN : count, SADR : string, ADR : string, Hop_Count : count, APDU : string)
    {
	minitracker(c, NPDU, APDU);
    }

event bacnet_ethernet_NPDU_SD(c: connection, BVLC_Header : bacnet::BVLCHeaders, NPDU : bacnet::NPDUs, SNET : count, SLEN : count, DNET : count, DLEN : count, SADR : string, DADR : string, Hop_Count : count, APDU : string)
    {
	tracker(c, NPDU, APDU);
    }

#############################################################################################
# ----- This section contains two functions that take in the connection, NPDU, and payload (called APDU, but it's really not an APDU)
# ----- to looks for the Initialize-Routing-Table or Initialize-Routing-Table-ACK messages
#############################################################################################

function minitracker(c: connection, NPDU : bacnet::MiniNPDUs, APDU : string): count
	{
	#If the NPDU packet has a Message Type, parse the data
	if (NPDU$Control & 0x80 == 0x80)
		{
			local message_code 	: count = bytestring_to_count(APDU[0:1]);
			local num_ports 	: count;

			if (message_code == 0x06)
				{
					if (bytestring_to_count(APDU[1:2]) == 0)
						{
							SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$orig_h, c$id$orig_p)), SumStats::Observation($str="Table Request"));
							print fmt("%s Table Request: %s:%d --> Observation: Table Request", network_time(), c$id$orig_h, c$id$orig_p);

							SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$resp_h, c$id$resp_p)), SumStats::Observation($str="Table Request"));
							print fmt("%s Table Request: %s:%d --> Observation: Table Request", network_time(), c$id$resp_h, c$id$resp_p);
						}
						else
							{
								SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$orig_h, c$id$orig_p)), SumStats::Observation($str="Table Write"));
								print fmt("%s Table Request: %s:%d --> Observation: Table Write", network_time(), c$id$orig_h, c$id$orig_p);

								SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$resp_h, c$id$resp_p)), SumStats::Observation($str="Table Request"));
								print fmt("%s Table Request: %s:%d --> Observation: Table Request", network_time(), c$id$resp_h, c$id$resp_p);
							}
					
				}
			if (message_code == 0x07)
				{
					SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$resp_h, c$id$resp_p)), SumStats::Observation($str="ACK"));
					# SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d|%s:%d", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p)), SumStats::Observation($str=fmt("ACK", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p)));
					print fmt("%s Table ACK-rsp: %s:%d --> Observation: ACK", network_time(), c$id$resp_h, c$id$resp_p);

					SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$orig_h, c$id$orig_p)), SumStats::Observation($str="ACK"));
					print fmt("%s Table ACK-rsp: %s:%d --> Observation: ACK", network_time(), c$id$orig_h, c$id$orig_p);
				}


			
		}
		return 0;
	}

function tracker(c: connection, NPDU : bacnet::NPDUs, APDU : string): count
	{
	#If the NPDU packet has a Message Type, parse the data
	if (NPDU$Control & 0x80 == 0x80)
		{
			local message_code 	: count = bytestring_to_count(APDU[0:1]);
			local num_ports 	: count;

			if (message_code == 0x06)
				{
					if (bytestring_to_count(APDU[1:2]) == 0)
						{
							SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$orig_h, c$id$orig_p)), SumStats::Observation($str="Table Request"));
							print fmt("%s Table Request: %s:%d --> Observation: Table Request", network_time(), c$id$orig_h, c$id$orig_p);

							SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$resp_h, c$id$resp_p)), SumStats::Observation($str="Table Request"));
							print fmt("%s Table Request: %s:%d --> Observation: Table Request", network_time(), c$id$resp_h, c$id$resp_p);
						}
						else
							{
								SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$orig_h, c$id$orig_p)), SumStats::Observation($str="Table Write"));
								print fmt("%s Table Request: %s:%d --> Observation: Table Write", network_time(), c$id$orig_h, c$id$orig_p);

								SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$resp_h, c$id$resp_p)), SumStats::Observation($str="Table Request"));
								print fmt("%s Table Request: %s:%d --> Observation: Table Request", network_time(), c$id$resp_h, c$id$resp_p);
							}
					
				}
			if (message_code == 0x07)
				{
					SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$resp_h, c$id$resp_p)), SumStats::Observation($str="ACK"));
					# SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d|%s:%d", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p)), SumStats::Observation($str=fmt("ACK", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p)));
					print fmt("%s Table ACK-rsp: %s:%d --> Observation: ACK", network_time(), c$id$resp_h, c$id$resp_p);

					SumStats::observe("bacnet.Router_Init", SumStats::Key($str=fmt("%s:%d", c$id$orig_h, c$id$orig_p)), SumStats::Observation($str="ACK"));
					print fmt("%s Table ACK-rsp: %s:%d --> Observation: ACK", network_time(), c$id$orig_h, c$id$orig_p);
				}


			
		}
		return 0;
	}