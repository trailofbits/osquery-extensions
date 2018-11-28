#include "globals.h"

#include <pubsub/servicemanager.h>

namespace trailofbits {
BCCProcessEventsServiceRef process_events_service;

osquery::Status initializeProcessEventsService() {
  return ServiceManager::instance().createService<BCCProcessEventsService>(
      process_events_service, 2U);
}

void releaseProcessEventsService() {
  process_events_service.reset();
}
} // namespace trailofbits
