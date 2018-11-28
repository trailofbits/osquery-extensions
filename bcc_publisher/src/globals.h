#pragma once

#include "bccprocesseventsservice.h"

#include <osquery/sdk.h>

namespace trailofbits {
extern BCCProcessEventsServiceRef process_events_service;

osquery::Status initializeProcessEventsService();
void releaseProcessEventsService();
} // namespace trailofbits
