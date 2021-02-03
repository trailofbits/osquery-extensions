/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include "mdm_status_extension.h"

#include <trailofbits/extutils.h>

#include <osquery/logger/logger.h>

#include <boost/asio.hpp>
#include <boost/process.hpp>

using namespace osquery;

namespace boostproc = boost::process;
namespace boostasio = boost::asio;

const std::string serverUrlStr = "ServerURL = \"";

TableColumns MDMStatusTablePlugin::columns() const {
    return {
        std::make_tuple("server_url", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("dep_enrollment", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("user_approved", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
}

TableRows MDMStatusTablePlugin::generate(QueryContext& request) {
    TableRows result;

    auto r = make_table_row();

    std::vector<std::string> systemProfileArgs = {"SPConfigurationProfileDataType"};

    trailofbits::ProcessOutput systemProfilerOutput;
    if (!ExecuteProcess(systemProfilerOutput, "/usr/sbin/system_profiler", systemProfileArgs) ||
            systemProfilerOutput.exit_code != 0) {
        VLOG(1) << "error running system_profiler: " << systemProfilerOutput.std_error;
        return result;
    }

    std::string &std_out = systemProfilerOutput.std_output;
    auto serverUrlLineStart = std_out.find(serverUrlStr);
    if (serverUrlLineStart != std::string::npos) {
        auto serverUrlLineEnd = std_out.find("\";", serverUrlLineStart);
        r["server_url"] = std_out.substr(serverUrlLineStart + serverUrlStr.length(),
                                         serverUrlLineEnd - serverUrlLineStart - serverUrlStr.length());
    } else {
        //no data found, not enrolled
        return result;
    }

    trailofbits::ProcessOutput profilesOutput;
    std::vector<std::string> profileArgs = {"status", "-type", "enrollment"};
    if (!ExecuteProcess(profilesOutput, "/usr/bin/profiles", profileArgs) ||
            profilesOutput.exit_code != 0) {
        VLOG(1) << "error running profiles: " << profilesOutput.std_error;
        return result;
    }


    std_out = profilesOutput.std_output;
    auto DEPStatus = std_out.find("DEP: ");
    if (std::string::npos != DEPStatus) {
        auto yesPos = std_out.find("Yes", DEPStatus + 4);
        if (yesPos == std::string::npos || yesPos > std_out.find("\n", DEPStatus + 4)) {
            r["dep_enrollment"] = "0";
        } else {
            r["dep_enrollment"] = "1";
        }
    } else {
        r["dep_enrollment"] = "Unavailable";
    }

    if (std::string::npos != std_out.find("(User Approved)")) {
        r["user_approved"] = "1";
    } else {
        r["user_approved"] = "0";
    }

    result.push_back(std::move(r));
    return result;
}
