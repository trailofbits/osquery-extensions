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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/logger.h>

#include "system_log.h"

namespace pt = boost::property_tree;

constexpr size_t MAX_SIZE = 5000;

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
LogMonitor::~LogMonitor() {
  stop();
}

void LogMonitor::stop() {
  if (log_process.running()) {
    kill(log_process.id(), SIGTERM);
  }

  if (reading_thread.joinable()) {
    reading_thread.join();
  }
}

void LogMonitor::tearDown() {
  stop();
}

void LogMonitor::configure() {
  //process the configuration here
}

void process_log(LogMonitor *logMonitor) {
  std::stringstream buffer;
  std::string line;
  while (std::getline(logMonitor->log_output, line)) {
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
  try {
    log_process = bp::child("/usr/bin/log", 
                            "stream",
                            "--style",
                            "json",
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

