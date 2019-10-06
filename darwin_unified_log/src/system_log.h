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

#pragma once


#include <thread>
#include <mutex>
#include <vector>
#include <deque>


#include <signal.h>

#include "Version.h"

#include <boost/process.hpp>
#include <boost/asio.hpp>

#if OSQUERY_VERSION_NUMBER < OSQUERY_SDK_VERSION(4, 0)
#include <osquery/sdk.h>
#else
#include <osquery/sdk/sdk.h>
#endif

#include <iostream>

namespace bp = boost::process;

class LogMonitor {
  public:
    LogMonitor();
    ~LogMonitor();
    osquery::Status setUp();
    void configure();
    void tearDown();

    void getEntries(osquery::QueryData &);

  private:
    osquery::Status start_monitoring();
    void stop_monitoring();
    void addEntries(std::vector<std::string> entries);

    bp::child log_process;
    bp::ipstream log_output;
    std::thread reading_thread;
    std::deque<osquery::Row> entries;

    std::string log_level;
    std::string log_predicate;
    std::mutex entry_lock;

    std::mutex process_management_lock;
    std::atomic<bool> is_shutting_down;

    friend void process_log(LogMonitor *logMonitor);

};
