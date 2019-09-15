
module bacnet;

export {
	## Standard BACnet BVLC Result codes.
	const BVLC_result_codes = {
		[0x0000] = "Successful completion",
		[0x0010] = "Write-Broadcast-Distribution-Table NAK",
		[0x0020] = "Read-Broadcast-Distribution-Table NAK",
		[0x0030] = "Register-Foreign-Device NAK",
		[0x0040] = "Read-Foreign-Device-Table NAK",
		[0x0050] = "Delete-Foreign-Device-Table-Entry NAK",
		[0x0060] = "Distribute-Broadcast-To-Network NAK",
	} &default=function(i: count):string { return fmt("Unknown BVLC Result code: %d", i); } &redef;

	## Standard BACnet BVLC Function codes.
	const BVLC_function_codes = {
		[0x00] = "BVLC-Result",
		[0x01] = "BVLC-Write-Broadcast-Distribution-Table",
		[0x02] = "BVLC-Read-Broadcast-Distribution-Table",
		[0x03] = "BVLC-Read-Broadcast-Distribution-Table-Ack",
		[0x04] = "BVLC-Forwarded-NPDU",
		[0x05] = "BVLC-Register-Foreign-Device",
		[0x06] = "BVLC-Read-Foreign-Device-Table",
		[0x07] = "BVLC-Read-Foreign-Device-Table-Ack",
		[0x08] = "BVLC-Delete-Foreign-Device-Table-Entry",
		[0x09] = "BVLC-Distribute-Broadcast-To-Network",
		[0x0A] = "BVLC-Original-Unicast-NPDU",
		[0x0B] = "BVLC-Original-Broadcast-NPDU",
		[0x0C] = "BVLC-Secure-BVLL",
	} &default=function(i: count):string { return fmt("Unknown BVLC Function code: %d", i); } &redef;

	## Standard BACnet NPDU Priority Codes.
	const NPDU_prior_codes = {
		[0x00] = "Normal Message",
		[0x01] = "Urgent Message",
		[0x02] = "Critical Equipment Message",
		[0x03] = "Life Safety Message",
	} &default=function(i: count):string { return fmt("Unknown NPDU Priority code: %d", i); } &redef;

	## BACnet NPDU data_expect_reply messages.
	const NPDU_reply = {
		[0x00] = "Confirmed-Request-PDU, segment, or network layer message expecting a reply",
		[0x04] = "Other than a Confirmed-Request-PDU, segment, or network layer message expecting a reply",
	} &default=function(i: count):string { return fmt("Unknown NPDU data_expect_reply code: %d", i); } &redef;



	## BACnet NPDU message types
	const NPDU_message_type = {
		[0x00] = "Who-Is-Router-To-Network",
		[0x01] = "I-Am-Router-To-Network",
		[0x02] = "I-Could-Be-Router-To-Network",
		[0x03] = "Reject-Message-To-Network",
		[0x04] = "Router-Busy-To-Network",
		[0x05] = "Router-Available-To-Network",
		[0x06] = "Initialize-Routing-Table",
		[0x07] = "Initialize-Routing-Table-Ack",
		[0x08] = "Establish-Connection-To-Network",
		[0x09] = "Disconnect-Connection-To-Network",
		[0x0A] = "Challenge-Request",
		[0x0B] = "Security-Payload",
		[0x0C] = "Security-Response",
		[0x0D] = "Request-Key-Update",
		[0x0E] = "Update-Key-Set",
		[0x0F] = "Update-Distribution-Key",
		[0x10] = "Request-Master-Key",
		[0x11] = "Set-Master-Key",
		[0x12] = "What-Is-Network-Number",
		[0x13] = "Network-Number-Is",
	} &default=function(i: count):string { return fmt("Not a standard message type number: %d", i); } &redef;

	
	## BACnet NPDU message types
	const Reject_Message = {
		[0x00] = "Other error",
		[0x01] = "The router is not directly connected to DNET and cannot find a router to DNET on any directly connected network using Who-Is-Router-To-Network messages",
		[0x02] = "The router is busy and unable to accept messages for the specified DNET at the present time",
		[0x03] = "It is an unknown network layer message type. The DNET returned in this case is a local matter",
		[0x04] = "The message is too long to be routed to this DNET",
		[0x05] = "The source message was rejected due to a BACnet security error and that error cannot be forwarded to the source device",
		[0x06] = "The source message was rejected due to errors in the addressing. The length of the DADR or SADR was determined to be invalid",
	} &default=function(i: count):string { return fmt("Not a defined rejection number: %d", i); } &redef;


	## BACnet APDU message types
	const APDU_message_type = {
		[0x0] = "Confirmed-Request-PDU",
		[0x1] = "Unconfirmed-Request-PDU",
		[0x2] = "Simple-ACK-PDU",
		[0x3] = "Complex-ACK-PDU",
		[0x4] = "Segment-ACK-PDU",
		[0x5] = "Error-PDU",
		[0x6] = "Reject-PDU",
		[0x7] = "Abort-PDU",
	} &default=function(i: count):string { return fmt("Not a defined APDU Type number: %d", i); } &redef;

	## BACnet APDU maximum segment enumeration
	const APDU_Max_Segs = {
		[0] = "Unspecified",
		[1] = "2 Segments accepted",
		[2] = "4 Segments accepted",
		[3] = "8 Segments accepted",
		[4] = "16 Segments accepted",
		[5] = "32 Segments accepted",
		[6] = "64 Segments accepted",
		[7] = ">64 Segments accepted",
	} &default=function(i: count):string { return fmt("Max segmenets invalid: %d", i); } &redef;

	## BACnet APDU maximum response / APDU length enumeration
	const APDU_Max_Resp = {
		[0x00] = "Up to 50 bytes",
		[0x01] = "Up to 128 bytes",
		[0x02] = "Up to 206 bytes (fits in a LonTalk frame)",
		[0x03] = "Up to 480 bytes (fits in an ARCNET frame)",
		[0x04] = "Up to 1024 bytes",
		[0x05] = "Up to 1476 bytes (fits in an Ethernet frame)",
	} &default=function(i: count):string { return fmt("Max APDU response size is reserved by ASHRAE: %d", i); } &redef;

	## BACnet APDU service choice types
	const APDU_C_Service = {
		[0] = "acknowledge-alarm",
		[1] = "confirmed-cov-notification",
		[2] = "confirmed-event-notification",
		[3] = "get-alarm-summary",
		[4] = "get-enrollment-summary",
		[5] = "subscribe-cov",
		[6] = "atomic-read-file",
		[7] = "atomic-write-file",
		[8] = "add-list-element",
		[9] = "remove-list-element",
		[10] = "create-object",
		[11] = "delete-object",
		[12] = "read-property",
		[13] = "read-property-conditional (removed in BACnet v1 rev 12)",
		[14] = "read-property-multiple",
		[15] = "write-property",
		[16] = "write-property-multiple",
		[17] = "device-communication-control",
		[18] = "confirmed-private-transfer",
		[19] = "confirmed-text-message",
		[20] = "reinitialize-device",
		[21] = "virtual-terminal-open",
		[22] = "virtual-terminal-close",
		[23] = "virtual-terminal-data",
		[24] = "authenticate (removed in BACnet v1 rev 11)",
		[25] = "request-key (removed in BACnet v1 rev 11)",
		[26] = "read-range",
		[27] = "life-safety-operation",
		[28] = "subscribe-cov-property",
		[29] = "get-event-information",
		[30] = "subscribe-cov-property-multiple",
		[31] = "confirmed-cov-notification-multiple",
	} &default=function(i: count):string { return fmt("Not a defined APDU Confirmed Serivce number: %d", i); } &redef;

	## BACnet APDU Reject enumerations
	const APDU_Reject = {
		[0x00] = "other",
		[0x01] = "buffer-overflow",
		[0x02] = "inconsistent-parameters",
		[0x03] = "invalid-parameter-data-type",
		[0x04] = "invalid-tag",
		[0x05] = "missing-required-parameter",
		[0x06] = "parameter-out-of-range",
		[0x07] = "too-many-arguments",
		[0x08] = "undefined-enumeration",
		[0x09] = "unrecognized-service",
	} &default=function(i: count):string { return fmt("Reserved by ASHRAE or vendor specific rejection code: %d", i); } &redef;

	## BACnet APDU Abort enumerations
	const APDU_Abort = {
		[0x00] = "other",
		[0x01] = "buffer-overflow",
		[0x02] = "invalid-apdu-in-this-state",
		[0x03] = "preempted-by-higher-priority-task",
		[0x04] = "segmentation-not-supported",
		[0x05] = "security-error",
		[0x06] = "insufficient-security",
		[0x07] = "window-size-out-of-range",
		[0x08] = "application-exceeded-reply-time",
		[0x09] = "out-of-resources",
		[0x0A] = "tsm-timeout",
		[0x0B] = "apdu-too-long",
	} &default=function(i: count):string { return fmt("Reserved by ASHRAE or vendor specific abort code: %d", i); } &redef;



}
