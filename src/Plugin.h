
#ifndef BRO_PLUGIN_HELLER_BACNET
#define BRO_PLUGIN_HELLER_BACNET

#include <plugin/Plugin.h>

namespace plugin {
namespace Heller_bacnet {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
