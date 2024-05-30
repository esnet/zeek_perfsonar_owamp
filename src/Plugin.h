#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin {
namespace PerfSONAR_OWAMP {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}