%include binpac.pac
%include bro.pac

%extern{
#include "bacnet.h"
#include "events.bif.h"
%}

analyzer bacnet withcontext {
    connection: bacnet_Conn;
    flow:       bacnet_Flow;
};

connection bacnet_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = bacnet_Flow(true);
    downflow = bacnet_Flow(false);
};

%include bacnet-protocol.pac

flow bacnet_Flow(is_orig: bool) {
	datagram = BACNET_PDU(is_orig) withcontext(connection, this);
};

%include bacnet-analyzer.pac
