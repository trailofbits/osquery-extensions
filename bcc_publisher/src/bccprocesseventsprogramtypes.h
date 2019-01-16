#pragma once

#include <probes/common/definitions.h>
#include <probes/common/utilities.h>

#include <probes/create_mknod_events.h>
#include <probes/dup_close_events.h>
#include <probes/exec_events.h>
#include <probes/fork_events.h>
#include <probes/open_events.h>
#include <probes/socket_fd_events.h>

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
      SysExitCreat = EVENTID_SYSEXITCREAT,

      SysEnterMknod = EVENTID_SYSENTERMKNOD,
      SysExitMknod = EVENTID_SYSEXITMKNOD,

      SysEnterMknodat = EVENTID_SYSENTERMKNODAT,
      SysExitMknodat = EVENTID_SYSEXITMKNODAT,

      SysEnterOpen = EVENTID_SYSENTEROPEN,
      SysExitOpen = EVENTID_SYSEXITOPEN,

      SysEnterOpenat = EVENTID_SYSENTEROPENAT,
      SysExitOpenat = EVENTID_SYSEXITOPENAT,

      SysEnterOpen_by_handle_at = EVENTID_SYSENTEROPEN_BY_HANDLE_AT,
      SysExitOpen_by_handle_at = EVENTID_SYSEXITOPEN_BY_HANDLE_AT,

      SysEnterName_to_handle_at = EVENTID_SYSENTERNAME_TO_HANDLE_AT,
      SysExitName_to_handle_at = EVENTID_SYSEXITNAME_TO_HANDLE_AT,

      SysEnterClose = EVENTID_SYSENTERCLOSE,
      SysExitClose = EVENTID_SYSEXITCLOSE,

      SysEnterDup = EVENTID_SYSENTERDUP,
      SysExitDup = EVENTID_SYSEXITDUP,

      SysEnterDup2 = EVENTID_SYSENTERDUP2,
      SysExitDup2 = EVENTID_SYSEXITDUP2,

      SysEnterDup3 = EVENTID_SYSENTERDUP3,
      SysExitDup3 = EVENTID_SYSEXITDUP3,

      SysEnterSocket = EVENTID_SYSENTERSOCKET,
      SysExitSocket = EVENTID_SYSEXITSOCKET,

      SysEnterSocketpair = EVENTID_SYSENTERSOCKETPAIR,
      SysExitSocketpair = EVENTID_SYSEXITSOCKETPAIR
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
    bool argv_truncated;
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
    std::uint64_t clone_flags;
    std::uint32_t parent_tid;
    std::uint32_t child_tid;
  };

  struct CreateData final {
    std::string path;
    mode_t mode;
  };

  struct MknodData final {
    std::string path;
    mode_t mode;
    dev_t dev;
  };

  struct MknodatData final {
    int dfd;
    std::string filename;
    mode_t mode;
    dev_t dev;
  };

  struct OpenData final {
    std::string filename;
    int flags;
    mode_t mode;
  };

  struct OpenatData final {
    int dfd;
    std::string filename;
    int flags;
    mode_t mode;
  };

  struct OpenByHandleAtData final {
    int mountdirfd;
    int flags;
  };

  struct NameToHandleAtData final {
    int dfd;
    std::string name;
    int mntid;
    int flag;
  };

  struct CloseData final {
    int fd;
  };

  struct DupData final {
    int fildes;
  };

  struct Dup2Data final {
    int oldfd;
    int newfd;
  };

  struct Dup3Data final {
    int oldfd;
    int newfd;
    int flags;
  };

  struct SocketData final {
    int family;
    int type;
    int protocol;
  };

  struct SocketpairData final {
    int family;
    int type;
    int protocol;
    int socketpair[2];
  };

  Header header;
  boost::optional<PidVnrData> namespace_data;
  boost::variant<ExecData,
                 PidVnrData,
                 ExitData,
                 CloneData,
                 CreateData,
                 MknodData,
                 MknodatData,
                 OpenData,
                 OpenatData,
                 OpenByHandleAtData,
                 NameToHandleAtData,
                 CloseData,
                 DupData,
                 Dup2Data,
                 Dup3Data,
                 SocketData,
                 SocketpairData>
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
