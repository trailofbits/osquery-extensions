/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "trailofbits/extutils.h"

#ifdef OSQUERY_WINDOWS
// Note: osquery defines _WIN32_WINNT as _WIN32_WINNT_WIN7,
// though Asio doesn't have that definition unless we include sdkddkver.h.
// Not finding the correct version will disable IOCP and will fail to compile.
#include <sdkddkver.h>
#endif
#include <boost/asio.hpp>
#include <boost/process.hpp>

namespace trailofbits {
namespace boostproc = boost::process;
namespace boostasio = boost::asio;

bool ExecuteProcess(ProcessOutput& output,
                    const std::string& path,
                    const std::vector<std::string>& args) {
  output = {};

  try {
    std::future<std::string> process_stdout;
    std::future<std::string> process_stderr;

    boostasio::io_service io_service;

    // clang-format off
    boostproc::child process(
      path, boostproc::args(args),
      boostproc::std_out > process_stdout,
      boostproc::std_err > process_stderr,
      io_service
    );
    // clang-format on

    io_service.run();

    // wait for the child process to get correct exit code
    // https://www.boost.org/doc/libs/1_71_0/doc/html/boost/process/child.html#idm45477675646672-bb
    process.wait();

    output.std_output = process_stdout.get();
    output.std_error = process_stderr.get();
    output.exit_code = process.exit_code();

#ifdef _WIN32
    if (output.exit_code == 259) {
      output.exit_code = 0;
    }
#endif

    return true;

  } catch (const std::exception&) {
    return false;
  }
}

bool ExecuteProcess(ProcessOutput& output,
                    const std::string& path,
                    const std::vector<std::string>& args,
                    const std::string& input) {
  output = {};

  try {
    std::future<std::string> process_stdout;
    std::future<std::string> process_stderr;

    boostasio::io_service io_service;
    boostproc::async_pipe process_stdin(io_service);

    // clang-format off
    boostproc::child process(
      path, boostproc::args(args),
      boostproc::std_out > process_stdout,
      boostproc::std_err > process_stderr,
      boostproc::std_in < process_stdin,
      io_service
    );
    // clang-format on

    // clang-format off
    boostasio::async_write(
      process_stdin, boostasio::buffer(input),

      [&](boost::system::error_code, size_t) {
        process_stdin.close();
      }
    );
    // clang-format on

    io_service.run();

    output.std_output = process_stdout.get();
    output.std_error = process_stderr.get();
    output.exit_code = process.exit_code();

    return true;

  } catch (...) {
    return false;
  }
}

std::vector<std::string> SplitString(const std::string& buffer,
                                     char delimiter) {
  std::istringstream stream(buffer);

  std::vector<std::string> output;
  for (std::string str; std::getline(stream, str, delimiter);) {
    boost::algorithm::trim(str);
    output.push_back(str);
  }

  return output;
}
} // namespace trailofbits
