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

#include <boost/process.hpp>
#include <boost/asio.hpp>

#include <osquery/sdk.h>

namespace bp = boost::process;

class LogMonitor {
  public:
    ~LogMonitor();
    osquery::Status setUp();
    void configure();
    void tearDown();

    void getEntries(osquery::QueryData &);

  private:
    void stop();
    void addEntries(std::vector<std::string> entries);

    bp::child log_process;
    bp::ipstream log_output;
    std::thread reading_thread;
    std::deque<osquery::Row> entries;

    std::mutex entry_lock;

    friend void process_log(LogMonitor *logMonitor);

};
