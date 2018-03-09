#pragma once

#include <string>
#include <vector>

namespace trailofbits {
struct ProcessOutput final {
  std::string std_output;
  std::string std_error;
  int exit_code;
};

bool ExecuteProcess(ProcessOutput& output,
                    const std::string& path,
                    const std::vector<std::string>& args);

bool ExecuteProcess(ProcessOutput& output,
                    const std::string& path,
                    const std::vector<std::string>& args,
                    const std::string& input);

std::vector<std::string> SplitString(const std::string& buffer, char delimiter);
} // namespace trailofbits
