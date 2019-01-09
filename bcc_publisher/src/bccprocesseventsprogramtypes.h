#pragma once

#include <bcc_probe_fork_events.h>
#include <fork_events/fork_events.h>

#include <bcc_probe_exec_events.h>
#include <exec_events/exec_events.h>

#include <bcc_probe_fd_events.h>
#include <fd_events/fd_events.h>

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

      KprobePidvnr = EVENTID_PIDVNR,

      SysEnterCreat = EVENTID_SYSENTERCREAT,
      SysEnterMknod = EVENTID_SYSENTERMKNOD,
      SysEnterMknodat = EVENTID_SYSENTERMKNODAT,
      SysEnterOpen = EVENTID_SYSENTEROPEN,
      SysEnterOpenat = EVENTID_SYSENTEROPENAT,
      SysEnterOpen_by_handle_at = EVENTID_SYSENTEROPEN_BY_HANDLE_AT,
      SysEnterName_to_handle_at = EVENTID_SYSENTERNAME_TO_HANDLE_AT,
      SysEnterClose = EVENTID_SYSENTERCLOSE,
      SysEnterDup = EVENTID_SYSENTERDUP,
      SysEnterDup2 = EVENTID_SYSENTERDUP2,
      SysEnterDup3 = EVENTID_SYSENTERDUP3,
      SysEnterSocket = EVENTID_SYSENTERSOCKET,
      SysEnterSocketpair = EVENTID_SYSENTERSOCKETPAIR
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

  struct CloneData final {
    std::uint64_t clone_flags{0U};
    std::uint32_t parent_tid{0U};
    std::uint32_t child_tid{0U};
  };

  struct OpenCreateData final {
    int folder_fd{-1};
    mode_t open_mode{0};
    int flags{0};
    dev_t device{0};

    std::string path;
  };

  Header header;
  boost::optional<PidVnrData> namespace_data;
  boost::variant<PidVnrData, ExecData, ExitData, CloneData, OpenCreateData>
      data;
};

using SyscallEventMap = std::unordered_map<pid_t, SyscallEvent>;

struct BCCProcessEventsContext final {
  SyscallEventMap fork_event_map;
  SyscallEventMap vfork_event_map;
  SyscallEventMap clone_event_map;
  SyscallEventMap clone_thread_event_map;

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
