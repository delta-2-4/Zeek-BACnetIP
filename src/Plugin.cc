
#include "Plugin.h"
#include "bacnet.h"

namespace plugin { namespace Heller_bacnet { Plugin plugin; } }

using namespace plugin::Heller_bacnet;

plugin::Configuration Plugin::Configure()
	{
	auto c = new ::analyzer::Component("bacnet",
	    ::analyzer::bacnet::bacnet_Analyzer::Instantiate);
	AddComponent(c);
	plugin::Configuration config;
	config.name = "Heller::bacnet";
	config.description = "BACnet protocol analyzer";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
