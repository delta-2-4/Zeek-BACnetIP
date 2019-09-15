#ifndef ANALYZER_PROTOCOL_BACNET_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_BACNET_H

#include "analyzer/protocol/udp/UDP.h"
#include "analyzer/protocol/pia/PIA.h"

namespace binpac  {
   namespace bacnet {
	   class bacnet_Conn;
   }
}

namespace analyzer { namespace bacnet {

class bacnet_Analyzer : public analyzer::Analyzer {
public:
	bacnet_Analyzer(Connection* conn);
	virtual ~bacnet_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
	                           uint64 seq, const IP_Hdr* ip,
	                           int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new bacnet_Analyzer(conn); }

protected:
	int did_session_done;

	bool orig_done;
	bool resp_done;

	pia::PIA_UDP* pia;
	binpac::bacnet::bacnet_Conn* interp;
};

} } // namespace analyzer::* 

#endif
