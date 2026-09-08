#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Hooks.h"
#include "InteeBtn.h"
#include "PickupFilter.h"
#include "InteeProbe.h"
#include "Logger.h"

namespace Hooks
{
    bool Init()
    {
        LOG_MSG("Hooks", "Initializing hooks ...");
        InteeBtn::Init();

        const bool pickupFilter = PickupFilter::Init();
        const bool interaction  = InteeProbe::Init();
        LOG("Hooks", "pickup-filter=%s interaction-probe=%s",
            pickupFilter ? "ok" : "failed",
            interaction ? "ok" : "failed");
        return pickupFilter || interaction;
    }

    void Uninit()
    {
        InteeProbe::Uninit();
        PickupFilter::Uninit();
        LOG_MSG("Hooks", "All hooks uninstalled");
    }
}