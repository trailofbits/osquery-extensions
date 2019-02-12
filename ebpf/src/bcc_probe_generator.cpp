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

#include "bcc_probe_generator.h"

#include <bcc_kprobe_header.h>
#include <bcc_probe_api.h>

#include <fstream>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

#include "osquery/core/conversions.h"

namespace boostfs = boost::filesystem;

namespace trailofbits {
namespace {
std::ostream& operator<<(std::ostream& stream,
                         ProbeParameter::Type tracepoint_param_type) {
  switch (tracepoint_param_type) {
  case ProbeParameter::Type::SignedInteger:
    stream << "SignedInteger";
    break;

  case ProbeParameter::Type::UnsignedInteger:
    stream << "UnsignedInteger";
    break;

  case ProbeParameter::Type::String:
    stream << "String";
    break;

  case ProbeParameter::Type::StringList:
    stream << "StringList";
    break;

  case ProbeParameter::Type::ByteArray:
    stream << "ByteArray";
    break;

  default:
    stream << "<INVALID_TRACEPOINT_PARAMETER_TYPE>";
    break;
  }

  return stream;
}

std::string generateTracepointHandler(
    const ManagedTracepointDescriptor& tracepoint_desc,
    std::uint16_t tracepoint_id,
    std::size_t string_buffer_size,
    const std::vector<pid_t>& osquery_pid_list) {
  bool enable_string_buffer = false;

  for (const auto& parameter : tracepoint_desc.parameter_list) {
    if (parameter.type == ProbeParameter::Type::String ||
        parameter.type == ProbeParameter::Type::ByteArray ||
        parameter.type == ProbeParameter::Type::StringList) {
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
    if (parameter.type == ProbeParameter::Type::String ||
        parameter.type == ProbeParameter::Type::StringList) {
      buffer << "  save" << parameter.type << "(string_buffer, ";

    } else if (parameter.type == ProbeParameter::Type::ByteArray) {
      buffer << "  save" << parameter.type << "(string_buffer, (const char *) ";

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

osquery::Status generateManagedTracepointProbeSource(
    std::string& probe_source_code, const ManagedTracepointProbe& desc) {
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

  buffer << kBccProbeAPI << "\n";

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

osquery::Status generateManagedTracepointProbe(
    eBPFProbeRef& probe, const ManagedTracepointProbe& desc) {
  std::string probe_source_code;
  auto status = generateManagedTracepointProbeSource(probe_source_code, desc);
  if (!status.ok()) {
    return status;
  }

  std::cout << probe_source_code << "\n\n" << std::endl;

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

osquery::Status generateKprobeProbe(eBPFProbeRef& probe,
                                    const KprobeProbe& desc) {
  eBPFProbeDescriptor probe_descriptor;
  probe_descriptor.name = desc.name;
  probe_descriptor.source_code = kBccKprobeHeader + "\n\n" + desc.source_code;

  for (const auto& kprobe : desc.kprobe_list) {
    eBPFProbeDescriptor::Probe probe = {};
    probe.type = eBPFProbeDescriptor::Probe::Type::Kprobe;
    probe.entry = kprobe.entry;
    probe.translate_name = kprobe.translate_name;
    probe.name = kprobe.name;

    probe_descriptor.probe_list.push_back(std::move(probe));
  }

  auto status = eBPFProbe::create(probe, probe_descriptor);
  if (!status.ok()) {
    return status;
  }

  return osquery::Status(0);
}
} // namespace trailofbits