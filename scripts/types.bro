
module bacnet;


export {

	type BVLCHeaders: record {
			Type:          count;
			Function:      count;
			Length:        count;

		};


	type NPDUs: record {
			IP	:	addr;
			Port	:	count;
			Version	:       count;
			Control	:       count;

		};

	type MiniNPDUs: record {
			Version	:       count;
			Control	:       count;

		};
	
}

module GLOBAL;