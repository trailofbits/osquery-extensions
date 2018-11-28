#pragma once

#include <bcc_probe_fork_events.h>
#include <fork_events/fork_events.h>

#include <bcc_probe_exec_events.h>
#include <exec_events/exec_events.h>

#include <boost/variant.hpp>
#include <osquery/sdk.h>

namespace trailofbits {
struct SyscallEvent final {
  struct Header final {
    enum class Type : std::uint32_t {
      SysEnterClone = EVENTID_SYSENTERCLONE,
      SysExitClone = EVENTID_SYSEXITCLONE,

      SysEnterFork = EVENTID_SYSENTERFORK,
      SysExitFork = EVENTID_SYSEXITFORK,

      SysEnterVfork = EVENTID_SYSENTERVFORK,
      SysExitVfork = EVENTID_SYSEXITVFORK,

      SysEnterExit = EVENTID_SYSENTEREXIT,
      SysEnterExitGroup = EVENTID_SYSENTEREXITGROUP,

      SysEnterExecve = EVENTID_SYSENTEREXECVE,
      SysExitExecve = EVENTID_SYSEXITEXECVE,

      SysEnterExecveat = EVENTID_SYSENTEREXECVEAT,
      SysExitExecveat = EVENTID_SYSEXITEXECVEAT,

      KprobePidvnr = EVENTID_PIDVNR
    };

    Type type;
    std::uint64_t timestamp;
    pid_t pid;
    pid_t tgid;
    uid_t uid;
    gid_t gid;
    boost::optional<int> exit_code;
  };

  struct ExecData final {
    std::string filename;
    std::vector<std::string> argv;
    bool argv_truncated{false};
  };

  struct PidVnrData final {
    std::size_t namespace_count;
    pid_t host_pid;
    std::vector<pid_t> namespaced_pid_list;
  };

  struct ExitData final {
    int error_code;
  };

  Header header;
  boost::variant<PidVnrData, ExecData, ExitData> data;
};

using SyscallEventMap = std::unordered_map<pid_t, SyscallEvent>;

struct BCCProcessEventsContext final {
  SyscallEventMap fork_event_map;
  SyscallEventMap vfork_event_map;
  SyscallEventMap clone_event_map;

  SyscallEventMap execve_event_map;
  SyscallEventMap execveat_event_map;
};

struct ProcessEvent final {
  enum class Type { Fork, Exec, Exit };

  struct ExecData final {
    std::string filename;
    std::vector<std::string> arguments;
    int exit_code;
  };

  struct ForkData final {
    pid_t child_pid;
    std::vector<pid_t> child_pid_namespaced;
  };

  struct ExitData final {
    int error_code;
  };

  Type type;

  std::uint64_t timestamp;
  pid_t pid;
  pid_t tgid;
  uid_t uid;
  gid_t gid;

  std::string docker_container_id;
  std::string docker_namespace_name;

  boost::variant<ExecData, ForkData, ExitData> data;
};

using ProcessEventList = std::map<std::uint64_t, ProcessEvent>;
} // namespace trailofbits
