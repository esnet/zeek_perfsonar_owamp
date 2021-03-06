// Generated by binpac_quickstart

#include "analyzer/Component.h"
#include "plugin/Plugin.h"

#include "OWAMP.h"

namespace plugin {
namespace PerfSONAR_OWAMP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("OWAMP",
		             ::analyzer::OWAMP::OWAMP_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "PerfSONAR::OWAMP";
		config.description = "One-Way Active Measurement Protocol analyzer";
		config.version.major = 0;
		config.version.minor = 1;

		return config;
		}
} plugin;

}
}
