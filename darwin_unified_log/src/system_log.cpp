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

#include <cstdlib>
#include <chrono>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/logger.h>

#include "system_log.h"

namespace pt = boost::property_tree;

constexpr size_t DEFAULT_MAX_SIZE = 5000;
size_t MAX_SIZE = DEFAULT_MAX_SIZE;

const std::string FIELD_NAMES[] = {"category",
                                   "activityID",
                                   "eventType",
                                   "processImageUUID",
                                   "processUniqueID",
                                   "threadID",
                                   "timestamp",
                                   "traceID",
                                   "messageType",
                                   "senderProgramCounter",
                                   "processID",
                                   "machTimestamp",
                                   "timezoneName",
                                   "subsystem",
                                   "eventMessage",
                                   "senderImageUUID",
                                   "processImagePath",
                                   "senderImagePath"};

const char* ENV_VAR_PREDICATE = "LOG_TABLE_PREDICATE";
const char* ENV_VAR_MAX_ENTRIES = "LOG_TABLE_MAX_ENTRIES";
const char* ENV_VAR_LOG_LEVEL = "LOG_TABLE_LEVEL";

LogMonitor::LogMonitor() : is_shutting_down(false) { }

LogMonitor::~LogMonitor() {
  tearDown();
}

void LogMonitor::stop_monitoring() {
  if (log_process.running()) {
    kill(log_process.id(), SIGTERM);
  }

  if (reading_thread.joinable()) {
    reading_thread.join();
  }

  log_output = bp::ipstream();
}

void LogMonitor::tearDown() {
  is_shutting_down = true;
  std::lock_guard<std::mutex> lock(process_management_lock);
  stop_monitoring();

}

void LogMonitor::configure() {
  auto max_entries_env = std::getenv(ENV_VAR_MAX_ENTRIES);
  if (nullptr != max_entries_env) {
    VLOG(1) << "found a max_entries in environment variables";
    try {
      MAX_SIZE = std::stoul(max_entries_env);
      VLOG(1) << "new MAX_SIZE is now " << MAX_SIZE;
    } catch (std::invalid_argument) {
      VLOG(1) << "invalid value for environment variable " << ENV_VAR_MAX_ENTRIES << ": " << max_entries_env;
    }
  } else {
    MAX_SIZE = DEFAULT_MAX_SIZE;
  }


  std::string old_log_predicate = log_predicate;
  auto predicate_env = std::getenv(ENV_VAR_PREDICATE);
  if (nullptr != predicate_env) {
    log_predicate = std::string(predicate_env);
  } else {
    log_predicate = "";
  }

  std::string old_log_level = log_level;
  auto log_level_env = std::getenv(ENV_VAR_LOG_LEVEL);
  if (nullptr != log_level_env) {
    log_level = std::string(log_level_env);
  } else {
    log_level = "";
  }


}

void process_log(LogMonitor *logMonitor) {
  std::stringstream buffer;
  std::string line;
  while (std::getline(logMonitor->log_output, line) && !logMonitor->is_shutting_down) {
    if (line[0] == '[' || line[0] == '}') {
      if (buffer.str().size()) {
        buffer << "}";
        logMonitor->addEntries({buffer.str()});
      }
      buffer.str("");
      buffer << "{";
    } else {
      buffer << line;
    }
  }
}


osquery::Status LogMonitor::setUp() {
  std::lock_guard<std::mutex> lock(process_management_lock);
  configure();

  return start_monitoring();
}

osquery::Status LogMonitor::start_monitoring() {
  if (log_process.running()) {
    return osquery::Status(1, "setUp called but log monitoring process already running");
  }

  try {
    std::vector<std::string> log_args = {"stream", "--style", "json"};
    if (log_predicate.size()) {
      log_args.push_back("--predicate");
      log_args.push_back(log_predicate);
      VLOG(1) << "applying log_predicate of \"" << log_predicate << "\"";
    }

    if (log_level.size()) {
      log_args.push_back("--level");
      log_args.push_back(log_level);
      VLOG(1) << "applying log_level of \"" << log_level << "\"";
    }

    log_process = bp::child("/usr/bin/log", 
                            bp::args(log_args),
                            bp::std_in.close(),
                            bp::std_out > log_output,
                            bp::std_err > bp::null);

    reading_thread = std::thread(process_log, this);

    return osquery::Status(0, "OK");
  } catch (std::exception &e) {
    VLOG(1) << "Error starting log monitoring process: " << e.what();
  }
  return osquery::Status(1, "Error starting log monitoring process");
}

void LogMonitor::getEntries(osquery::QueryData &q) {
  std::lock_guard<std::mutex> lock(entry_lock);
  for (auto elem : entries) {
    q.push_back(elem);
  }
}

void LogMonitor::addEntries(std::vector<std::string> entry_strings) {
  std::vector<osquery::Row> new_entries;
  for (auto str : entry_strings) {
    try {
      std::stringstream s(str);
      pt::ptree t;
      pt::read_json(s, t);

      osquery::Row r;
      for (auto field : FIELD_NAMES) {
        r[field] = t.get<std::string>(field, "");
      }
      new_entries.push_back(r);
    } catch(std::exception &e) {
      VLOG(1) << "error parsing entry: " << e.what();
    }
  }

  std::lock_guard<std::mutex> lock(entry_lock);
  for (auto entry : new_entries) {
    entries.push_back(entry);
  }
  while (entries.size() > MAX_SIZE) {
    entries.pop_front();
  }
}

