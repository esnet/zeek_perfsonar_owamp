
#ifndef BRO_PLUGIN_PERFSONAR_OWAMP
#define BRO_PLUGIN_PERFSONAR_OWAMP

#include <plugin/Plugin.h>

namespace plugin {
namespace PerfSONAR_OWAMP {

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
