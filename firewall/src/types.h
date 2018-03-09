#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace trailofbits {
using PrimaryKey = std::string;
using RowID = std::uint64_t;
using RowIdToPrimaryKeyMap = std::unordered_map<RowID, PrimaryKey>;
} // namespace trailofbits
