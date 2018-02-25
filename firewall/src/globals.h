#pragma once

#include <memory>
#include <trailofbits/ifirewall.h>

namespace trailofbits {
extern std::unique_ptr<IFirewall> firewall;
}
