#include "bacnet.h"
#include "bacnet_pac.h"

using namespace analyzer::bacnet;

bacnet_Analyzer::bacnet_Analyzer(Connection* conn)
: Analyzer("bacnet", conn)
	{
	interp = new binpac::bacnet::bacnet_Conn(this);
	did_session_done = 0;
	orig_done = resp_done = false;
	pia = 0;
	}

bacnet_Analyzer::~bacnet_Analyzer()
	{
	delete interp;
	}

void bacnet_Analyzer::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void bacnet_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                   uint64 seq, const IP_Hdr* ip,
                                   int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
