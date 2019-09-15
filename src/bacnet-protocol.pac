# The below parameters can be manipulated by the user in Zeek
	type BACNET_PDU(is_orig: bool) = record {
		BVLC_Header	: BVLC_Header_Type;
		BVLC_Data	: case BVLC_Header.Function of {
			0	-> BVLC_result			: BVLC_Result_Type(BVLC_Header);	# Done
			1	-> BVLC_write_broad_dist	: BVLC_BDT_Type(BVLC_Header);		# Done
			2	-> BVLC_read_broad_dist		: BVLC_Read_B_F(BVLC_Header);		# Done
			3 	-> BVLC_read_broad_dist_ACK	: BVLC_BDT_Type(BVLC_Header);		# Done
			4	-> BVLC_fwd_NPDU		: NPDU_Header_Type(BVLC_Header);	# APDU portion not done
			5	-> BVLC_reg_fdevice		: BVLC_RFD_Type(BVLC_Header);		# Done
			6	-> BVLC_read_fdevice		: BVLC_Read_B_F(BVLC_Header);		# Done
			7	-> BVLC_read_fdevice_ACK	: BVLC_Read_FDT_Ack_Type(BVLC_Header);  # Done, not tested
			8	-> BVLC_del_fdevice		: BVLC_Del_FD_Type(BVLC_Header);	# Done, not tested
			9	-> BVLC_distribute_broadcast	: NPDU_Header_No_Type(BVLC_Header);
			10	-> BVLC_unicast_NPDU		: NPDU_Header_No_Type(BVLC_Header);
			11	-> BVLC_broadcast_NPDU		: NPDU_Header_No_Type(BVLC_Header);
			12	-> BVLC_secure			: BVLC_Secure_Type(BVLC_Header);
			default	-> BVLC_unknown_data		: Unknown_Type(BVLC_Header);
		};



 } &let {
		#deliver: bool = $context.flow.deliver_BACnet_PDU(this);
} &byteorder=bigendian;


#BACnet BVLC Header Type
	type BVLC_Header_Type = record {
		Type 		: uint8;
		Function 	: uint8;
		Length		: uint16;
	};


#BVLC Result Type
	type BVLC_Result_Type(BVLC_Header : BVLC_Header_Type) = record {

		Result		: uint16;

	} &let {
			deliver: bool = $context.flow.deliver_BVLC_Result(BVLC_Header, this);

		} &byteorder=bigendian;

#BVLC Broadcast Distribution Table Type (read or write)
	type BVLC_BDT_Type(BVLC_Header : BVLC_Header_Type) = record {

		Table		: bytestring &restofdata;

	} &let {
			deliver: bool = $context.flow.deliver_BVLC_BDT(BVLC_Header, this);

		} &byteorder=bigendian;


#BVLC Read Broadcast Distribution Table or Foreign Device Table Type
	type BVLC_Read_B_F(BVLC_Header : BVLC_Header_Type) = record {
	} &let {
			deliver: bool = $context.flow.deliver_BVLC_BVLC_B_F(BVLC_Header);

		} &byteorder=bigendian;

#BVLC Register Foreign Device Type
	type BVLC_RFD_Type(BVLC_Header : BVLC_Header_Type) = record {

		TTL	: uint16;

	} &let {
			deliver: bool = $context.flow.deliver_BVLC_RFD(BVLC_Header, this);

		} &byteorder=bigendian;

#BVLC Read Foreign Device Table Ack Type
	type BVLC_Read_FDT_Ack_Type(BVLC_Header : BVLC_Header_Type) = record {

		Table		: bytestring &restofdata;

	} &let {
			deliver: bool = $context.flow.deliver_BVLC_Read_FDT_Ack(BVLC_Header, this);

		} &byteorder=bigendian;


#BVLC Delete Foreign Device Table Entry Type
	type BVLC_Del_FD_Type(BVLC_Header : BVLC_Header_Type) = record {

		Entry		: bytestring &restofdata;

	} &let {
			deliver: bool = $context.flow.deliver_BVLC_Del_FD(BVLC_Header, this);

		} &byteorder=bigendian;

#BVLC Secure Type
	type BVLC_Secure_Type(BVLC_Header : BVLC_Header_Type) = record {


		} &let {
			deliver: bool = $context.flow.deliver_BVLC_Secure(BVLC_Header);

		} &byteorder=bigendian;

#BVLC Unknown function (not defined by ASHRAE 135-2016)
	type Unknown_Type(BVLC_Header : BVLC_Header_Type) = record {
	} &let {
			deliver: bool = $context.flow.deliver_Unknown_BVLC(BVLC_Header);

		} &byteorder=bigendian;
# -----------------------------------------------------------NPDU


#BACnet NPDU Header Type

	type NPDU_Header_Type(BVLC_Header : BVLC_Header_Type) = record {
		IP	 	: uint32;
		Port	 	: uint16;
		Version		: uint8;
		Control 	: uint8;

		NPDU_Fields	: case (Control & 0xA8) of {

					0x80 -> MT_Present		: APDU_Type(BVLC_Header, this);
					0xA8 -> MT_Dst_Src_Present	: APDU_Src_Dst_Type(BVLC_Header, this);
					0xA0 -> MT_Dst_Present		: APDU_Dst_Type(BVLC_Header, this);
					0x88 -> MT_Src_Present		: APDU_Src_Type(BVLC_Header, this);
					0x28 -> APDU_Src_Dst_Present	: APDU_Src_Dst_Type(BVLC_Header, this);
					0x20 -> APDU_Dst_Present	: APDU_Dst_Type(BVLC_Header, this);
					0x08 -> APDU_Src_Present	: APDU_Src_Type(BVLC_Header, this);
					0x00 -> APDU_Present		: APDU_Type(BVLC_Header, this);
				};

	}&byteorder=bigendian;

#BACnet NPDU No Header Type
	type NPDU_Header_No_Type(BVLC_Header : BVLC_Header_Type) = record {
		Version		: uint8;
		Control 	: uint8;

		NPDU_Fields	: case (Control & 0xA8) of {

					0x80 -> MT_Present		: APDU_No_Type(BVLC_Header, this);
					0xA8 -> MT_Dst_Src_Present	: APDU_Src_Dst_No_Type(BVLC_Header, this);
					0xA0 -> MT_Dst_Present		: APDU_Dst_No_Type(BVLC_Header, this);
					0x88 -> MT_Src_Present		: APDU_Src_No_Type(BVLC_Header, this);
					0x28 -> APDU_Src_Dst_Present	: APDU_Src_Dst_No_Type(BVLC_Header, this);
					0x20 -> APDU_Dst_Present	: APDU_Dst_No_Type(BVLC_Header, this);
					0x08 -> APDU_Src_Present	: APDU_Src_No_Type(BVLC_Header, this);
					0x00 -> APDU_Present		: APDU_No_Type(BVLC_Header, this);
				};

	}&byteorder=bigendian;


# -------------------------------------------------APDU


#BACnet APDU and Destination fields present type
	type APDU_Dst_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_Type) = record{

		DNET		: uint16; 
		DLEN		: uint8;
		DADR_Present	: case (DLEN) of {

					0	-> DADR_Absent  :  empty;
					default	-> DADR		:  bytestring &length = DLEN;
				};
		Hop_Count	: uint8;
		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_Dst(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;



#BACnet APDU and Destination fields present type
	type APDU_Src_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_Type) = record{

		SNET		: uint16; 
		SLEN		: uint8;
		SADR		: bytestring &length = SLEN;

		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_Src(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;

#BACnet APDU, Source, and Destination fields present type
	type APDU_Src_Dst_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_Type) = record{

		DNET		: uint16; 
		DLEN		: uint8;
		DADR_Present	: case (DLEN) of {

					0	-> DADR_Absent  :  empty;
					default	-> DADR		:  bytestring &length = DLEN;
					};
		SNET		: uint16; 
		SLEN		: uint8;
		SADR		: bytestring &length = SLEN;
		Hop_Count	: uint8;
		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_Src_Dst(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;


#BACnet APDU, Source, and Destination fields present type
	type APDU_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_Type) = record{

		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;

# -----------------------------------------APDU No Types

#BACnet APDU and Destination fields present type
	type APDU_Dst_No_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_No_Type) = record{

		DNET		: uint16; 
		DLEN		: uint8;
		DADR_Present	: case (DLEN) of {

					0	-> DADR_Absent  :  empty;
					default	-> DADR		:  bytestring &length = DLEN;
				};
		Hop_Count	: uint8;
		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_Dst_No(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;



#BACnet APDU and Destination fields present type
	type APDU_Src_No_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_No_Type) = record{

		SNET		: uint16; 
		SLEN		: uint8;
		SADR		: bytestring &length = SLEN;

		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_Src_No(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;

#BACnet APDU, Source, and Destination fields present type
	type APDU_Src_Dst_No_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_No_Type) = record{

		DNET		: uint16; 
		DLEN		: uint8;
		DADR_Present	: case (DLEN) of {

					0	-> DADR_Absent  :  empty;
					default	-> DADR		:  bytestring &length = DLEN;
					};
		SNET		: uint16; 
		SLEN		: uint8;
		SADR		: bytestring &length = SLEN;
		Hop_Count	: uint8;
		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_Src_Dst_No(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;


#BACnet APDU, Source, and Destination fields present type
	type APDU_No_Type(BVLC_Header : BVLC_Header_Type, NPDU : NPDU_Header_No_Type) = record{

		APDU		: bytestring &restofdata;

	}&let {
			deliver: bool = $context.flow.deliver_APDU_No(BVLC_Header, NPDU, this);
		
		} &byteorder=bigendian;






#BACnet B/IP type
	type BIP = record {
		IP_addr	:	bytestring &length=4;
		UDP_prt	:	uint16;
	};

#BACnet B/IP and Broadcast Distribution Mask (BDM) for Broadcast Distribution Table
	type BDT_entry = record {
		BDT_BIP		:	BIP;
		BDM		:	uint32;
	};

#BACnet Foreign device table
	type FDT_entry = record {
		FDT_BIP		:	BIP;
		Reg_TTL		:	uint16;
		Remain_TTL	:	uint16;
	};






#The BACnet_NPD type describes the BACnet Network Protocol Data Unit (NPDU) portion of a BACnet packet
	type BACnet_NPDU = record {
	 	NPDU_Version	: uint8;	#Should be = 1

		NPDU_Control	: uint8;	#The value of NPDU_Control determines what other NPDU fields exist in the packet as well as if there is an APDU

		NPDU_Dst	: case (NPDU_Control & 0x20) of {
				0x20	-> Dst		: Dst_Type;		#Destination information fields only exist if NPDU_Control bit 5 = 1
				default -> nothing1	: empty;
		};


		NPDU_Src	: case (NPDU_Control & 0x8) of {
				0x8	-> Src		: Src_Type;		#Destination information fields only exist if NPDU_Control bit 5 = 1
				default -> nothing2	: empty;
		};


		NPDU_Hop_Count	: case (NPDU_Control & 0x20) of {
				0x20	-> Hop_Count	: uint8;		#Hop Count field only exist if NPDU_Control bit 5 = 1
				default -> nothing3	: empty;
		};


		NPDU_Msg_Type	: case (NPDU_Control & 0x80) of {

				0x80	-> N_Msg_Type	: Msg_Type;		#Msg_Type only exists if NPDU_Control bit 7 = 1
				0x00	-> APDU_Present	: uint8;		#An APDU only exists if NPDU_Control bit 7 = 0
		};

		Remaining_Data	: bytestring &restofdata;

};


#NPDU destiantion related fields
	type Dst_Type = record{

		NPDU_DNET	: uint16;

	#NPDU_DLEN should always be 6 for BACnet/IP since DADR shuld hold a MAC address, which is 6 octets long
		NPDU_DLEN	: uint8;
		NPDU_DADR	: bytestring &length = NPDU_DLEN;
	};

#NPDU source related fields
	type Src_Type = record{

		NPDU_SNET	: uint16;

	#NPDU_DLEN should always be 6 for BACnet/IP since DADR shuld hold a MAC address, which is 6 octets long
		NPDU_SLEN	: uint8;
		NPDU_SADR	: bytestring &length = NPDU_SLEN;
	};

#NPDU Mesage Type related fields
	type Msg_Type = record{
		
		NPDU_MSGTYPE	: uint8;
		NPDU_Vendor_ID	: case (NPDU_MSGTYPE & 0x80) of {
				0x80	-> Vendor_ID	: uint16;
				default -> nothing5	: empty;
				};
	};



