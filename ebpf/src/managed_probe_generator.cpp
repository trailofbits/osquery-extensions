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

#include "managed_probe_generator.h"

#include <fstream>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

#include "osquery/core/conversions.h"

namespace boostfs = boost::filesystem;

namespace trailofbits {
namespace {
static const std::string kManagedProbeHeader = R"PROBE_HEADER(
#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define EVENT_MAP_SIZE 1000000

#define VARARGS_TERMINATOR 0xFFFF0000FFFF0000ULL
#define VARARGS_TRUNCATION 0x0011001100110011ULL

#define BASE_EVENT_TYPE 0x1122334455660000ULL

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(perf_event_data, u64, EVENT_MAP_SIZE);
BPF_PERCPU_ARRAY(perf_cpu_index, u64, 1);

#define INCREMENT_EVENT_DATA_INDEX_BY(idx, amount) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % EVENT_MAP_SIZE

#define INCREMENT_EVENT_DATA_INDEX(idx) \
  INCREMENT_EVENT_DATA_INDEX_BY(idx, 1)

/// Saves the generic event header into the per-cpu map, returning the
/// initial index
static int saveEventHeader(u64 event_identifier,
                           u64 syscall_number,
                           bool save_exit_code,
                           int exit_code) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = perf_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int event_index = (index_ptr != NULL ? *index_ptr : initial_slot);

  int index = event_index;
  perf_event_data.update(&index, &event_identifier);
  INCREMENT_EVENT_DATA_INDEX(index);

  perf_event_data.update(&index, &syscall_number);
  INCREMENT_EVENT_DATA_INDEX(index);

  u64 field = bpf_ktime_get_ns();
  perf_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  field = bpf_get_current_pid_tgid();
  perf_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  field = bpf_get_current_uid_gid();
  perf_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  if (save_exit_code == true) {
    field = (u64)exit_code;
    perf_event_data.update(&index, &field);
    INCREMENT_EVENT_DATA_INDEX(index);
  }

  initial_slot = index; // re-use the same var to avoid wasting stack space
  perf_cpu_index.update(&index_key, &initial_slot);

  return event_index;
}

/// Saves the given string into the per-cpu map
static int saveStringBuffer(const char* buffer) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = perf_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

#pragma unroll
  for (int i = 0; i < STRING_BUFFER_SIZE / 8; i++) {
    perf_event_data.update(&index, (u64*)&buffer[i * 8]);
    INCREMENT_EVENT_DATA_INDEX(index);
  }

  initial_slot = index; // re-use the same var to avoid wasting stack space
  perf_cpu_index.update(&index_key, &initial_slot);

  return 0;
}

/// Saves the string pointed to by the given address into the per-cpu map
static bool saveString(char* buffer, const char* address) {
  if (address == NULL) {
    return false;
  }

  bpf_probe_read(buffer, STRING_BUFFER_SIZE, address);
  saveStringBuffer(buffer);

  return true;
}

#define saveByteArray saveStringBuffer

/// Saves the truncation identifier into the per-cpu map; used for varargs
/// functions likes execve
static int emitVarargsTerminator(bool truncated) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = perf_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

  u64 terminator = truncated == true ? VARARGS_TRUNCATION : VARARGS_TERMINATOR;
  perf_event_data.update(&index, &terminator);
  INCREMENT_EVENT_DATA_INDEX(index);

  initial_slot = index; // re-use the same var to avoid wasting stack space
  perf_cpu_index.update(&index_key, &initial_slot);

  return 0;
}

/// Saves the given value to the per-cpu buffer; only use after the header
/// has been sent
#define saveSignedInteger saveEventValue
#define saveUnsignedInteger saveEventValue
static int saveEventValue(u64 value) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = perf_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

  perf_event_data.update(&index, &value);
  INCREMENT_EVENT_DATA_INDEX(index);

  initial_slot = index; // re-use the same var to avoid wasting stack space
  perf_cpu_index.update(&index_key, &initial_slot);

  return 0;
}

static int saveStringList(char *buffer, const char *const * string_list) {
  const char* argument_ptr = NULL;

#pragma unroll
  for (int i = 1; i < STRING_LIST_SIZE; i++) {
    bpf_probe_read(&argument_ptr, sizeof(argument_ptr), &string_list[i]);
    if (saveString(buffer, argument_ptr) == false) {
      goto emit_terminator;
    }
  }

  goto emit_truncation;

emit_truncation:
  emitVarargsTerminator(true);
  return 0;

emit_terminator:
  emitVarargsTerminator(false);
  return 0;
}
)PROBE_HEADER";

std::ostream& operator<<(
    std::ostream& stream,
    ManagedProbeTracepoint::Parameter::Type tracepoint_param_type) {
  switch (tracepoint_param_type) {
  case ManagedProbeTracepoint::Parameter::Type::SignedInteger:
    stream << "SignedInteger";
    break;

  case ManagedProbeTracepoint::Parameter::Type::UnsignedInteger:
    stream << "UnsignedInteger";
    break;

  case ManagedProbeTracepoint::Parameter::Type::String:
    stream << "String";
    break;

  case ManagedProbeTracepoint::Parameter::Type::StringList:
    stream << "StringList";
    break;

  case ManagedProbeTracepoint::Parameter::Type::ByteArray:
    stream << "ByteArray";
    break;

  default:
    stream << "<INVALID_TRACEPOINT_PARAMETER_TYPE>";
    break;
  }

  return stream;
}

std::string generateTracepointHandler(
    const ManagedProbeTracepoint& tracepoint_desc,
    std::uint16_t tracepoint_id,
    std::size_t string_buffer_size,
    const std::vector<pid_t>& osquery_pid_list) {
  bool enable_string_buffer = false;

  for (const auto& parameter : tracepoint_desc.parameter_list) {
    if (parameter.type == ManagedProbeTracepoint::Parameter::Type::String ||
        parameter.type == ManagedProbeTracepoint::Parameter::Type::StringList) {
      enable_string_buffer = true;
      break;
    }
  }

  std::stringstream buffer;

  buffer << "int tracepoint_" << tracepoint_desc.name
         << "(struct tracepoint__syscalls__" << tracepoint_desc.name
         << "* args) {\n";

  buffer << "  pid_t current_pid = (bpf_get_current_pid_tgid() >> 32);\n";
  buffer << "  if (";

  for (auto pid_it = osquery_pid_list.begin(); pid_it != osquery_pid_list.end();
       pid_it++) {
    auto pid = *pid_it;

    buffer << "current_pid == " << pid;
    if (std::next(pid_it, 1) != osquery_pid_list.end()) {
      buffer << " || ";
    }
  }

  buffer << ") {\n";
  buffer << "    return 0;\n";
  buffer << "  }\n\n";

  bool enter_event = tracepoint_desc.name.find("sys_enter_") == 0U;
  buffer << "  int event_index = saveEventHeader(BASE_EVENT_TYPE | "
         << tracepoint_id << "ULL, args->__syscall_nr, ";

  if (enter_event) {
    buffer << "false, 0);\n";
  } else {
    buffer << "true, args->ret);\n";
  }

  if (enable_string_buffer) {
    buffer << "\n";
    buffer << "  char string_buffer[" << string_buffer_size << "] = {};\n";
  }

  if (!tracepoint_desc.parameter_list.empty()) {
    buffer << "\n";
  }

  for (const auto& parameter : tracepoint_desc.parameter_list) {
    if (parameter.type == ManagedProbeTracepoint::Parameter::Type::String ||
        parameter.type == ManagedProbeTracepoint::Parameter::Type::StringList) {
      buffer << "  save" << parameter.type << "(string_buffer, ";

    } else if (parameter.type ==
               ManagedProbeTracepoint::Parameter::Type::ByteArray) {
      buffer << "  save" << parameter.type << "((const char *) ";

    } else {
      buffer << "  save" << parameter.type << "(";
    }

    buffer << "args->" << parameter.name << ");\n";
  }

  buffer << "\n";

  buffer
      << "  u32 event_id = (((struct task_struct*) "
         "bpf_get_current_task())->cpu << 28) | (event_index & 0x00FFFFFF);\n";

  buffer << "  events.perf_submit(args, &event_id, sizeof(event_id));\n";
  buffer << "  return 0;\n";
  buffer << "}\n\n";

  std::cout << "\n\n======================\n"
            << buffer.str() << "\n=========================\n\n"
            << std::endl;

  return buffer.str();
}

osquery::Status getOsqueryPidList(std::vector<pid_t>& pid_list) {
  pid_list.clear();

  boostfs::path proc_folder("/proc");

  for (const auto& entry : boost::make_iterator_range(
           boostfs::directory_iterator(proc_folder), {})) {
    if (!boostfs::is_directory(entry)) {
      continue;
    }

    auto process_com_path = entry / "comm";

    std::ifstream comm_stream(process_com_path.string());

    std::string process_name((std::istreambuf_iterator<char>(comm_stream)),
                             std::istreambuf_iterator<char>());
    process_name.pop_back();

    if (process_name != "osqueryi" && process_name != "osqueryd") {
      continue;
    }

    std::cout << process_name << std::endl;

    auto pid =
        osquery::tryTo<pid_t>(entry.path().filename().string(), 10).takeOr(0);
    if (pid != 0) {
      pid_list.push_back(pid);
    }
  }

  if (pid_list.empty()) {
    return osquery::Status::failure("No running osquery found");
  }

  return osquery::Status(0);
}

osquery::Status generateManagedProbeSource(std::string& probe_source_code,
                                           const ManagedProbeDescriptor& desc) {
  probe_source_code.clear();

  std::vector<pid_t> osquery_pid_list;
  auto status = getOsqueryPidList(osquery_pid_list);
  if (!status.ok()) {
    return status;
  }

  osquery_pid_list.push_back(getpid());

  std::stringstream buffer;

  buffer << "#define STRING_BUFFER_SIZE " << desc.string_buffer_size << "\n";
  buffer << "#define STRING_LIST_SIZE " << desc.string_list_size << "\n\n";

  buffer << kManagedProbeHeader << "\n";

  std::size_t tracepoint_id = 0U;
  for (const auto& tracepoint_desc : desc.tracepoint_list) {
    auto tracepoint_handler = generateTracepointHandler(tracepoint_desc,
                                                        tracepoint_id++,
                                                        desc.string_buffer_size,
                                                        osquery_pid_list);

    buffer << tracepoint_handler;
  }

  probe_source_code = buffer.str();
  return osquery::Status(0);
}
} // namespace

osquery::Status generateManagedProbe(eBPFProbeRef& probe,
                                     const ManagedProbeDescriptor& desc) {
  std::string probe_source_code;
  auto status = generateManagedProbeSource(probe_source_code, desc);
  if (!status.ok()) {
    return status;
  }

  eBPFProbeDescriptor probe_descriptor;
  probe_descriptor.name = desc.name;
  probe_descriptor.source_code = probe_source_code;

  for (const auto& tracepoint : desc.tracepoint_list) {
    eBPFProbeDescriptor::Probe probe = {};
    probe.type = eBPFProbeDescriptor::Probe::Type::Tracepoint;
    probe.entry = (tracepoint.name.find("sys_enter_") != std::string::npos);
    probe.translate_name = true;
    probe.name = tracepoint.name;

    probe_descriptor.probe_list.push_back(std::move(probe));
  }

  status = eBPFProbe::create(probe, probe_descriptor);
  if (!status.ok()) {
    return status;
  }

  return osquery::Status(0);
}
} // namespace trailofbits