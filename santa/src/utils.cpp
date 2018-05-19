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

#include "utils.h"

#include <boost/asio.hpp>
#include <boost/process.hpp>

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

    output.std_output = process_stdout.get();
    output.std_error = process_stderr.get();
    output.exit_code = process.exit_code();

    return true;

  } catch (...) {
    return false;
  }
}