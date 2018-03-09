#include <boost/asio.hpp>
#include <boost/process.hpp>

#include <trailofbits/extutils.h>

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

    output.std_output = process_stdout.get();
    output.std_error = process_stderr.get();
    output.exit_code = process.exit_code();

    return true;

  } catch (...) {
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
