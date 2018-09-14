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

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include <osquery/logger.h>

#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

#include <sqlite3.h>

#include "santa.h"

const std::string kSantaLogPath = "/var/db/santa/santa.log";
const std::string kLogEntryPreface = "santad: ";

const std::string kSantaDatabasePath = "/var/db/santa/rules.db";
const std::string kTemporaryDatabasePath = "/tmp/rules.db";

std::list<std::string> archived_lines;
unsigned int next_oldest_archive = 0;

void extractValues(const std::string& line,
                   std::map<std::string, std::string>& values) {
  values.clear();

  // extract timestamp
  size_t timestamp_start = line.find("[");
  size_t timestamp_end = line.find("]");

  if (timestamp_start != std::string::npos &&
      timestamp_end != std::string::npos && timestamp_start != timestamp_end) {
    values["timestamp"] =
        line.substr(timestamp_start + 1, timestamp_end - timestamp_start - 1);
  }

  // extract key=value pairs after the kLogEntryPreface
  size_t key_pos = line.find(kLogEntryPreface);
  if (key_pos == std::string::npos) {
    return;
  }

  key_pos += kLogEntryPreface.length();
  size_t key_end, val_pos, val_end;
  while ((key_end = line.find('=', key_pos)) != std::string::npos) {
    if ((val_pos = line.find_first_not_of("=", key_end)) == std::string::npos) {
      break;
    }

    val_end = line.find('|', val_pos);
    values.emplace(line.substr(key_pos, key_end - key_pos),
                   line.substr(val_pos, val_end - val_pos));

    key_pos = val_end;
    if (key_pos != std::string::npos)
      ++key_pos;
  }
}

void scrapeStream(std::istream& incoming,
                  LogEntries& response,
                  bool save_to_archive,
                  SantaDecisionType decision) {
  std::string line;
  while (std::getline(incoming, line)) {
    if (decision == kAllowed) {
      // explicitly filter to only include ALLOW decisions
      if (line.find("decision=ALLOW") == std::string::npos) {
        continue;
      }
    } else /* if (decision == kDenied) */ {
      // explicitly filter to only include DENY decisions
      if (line.find("decision=DENY") == std::string::npos) {
        continue;
      }
    }

    std::map<std::string, std::string> values;
    extractValues(line, values);

    response.push_back({values["timestamp"],
                        values["path"],
                        values["reason"],
                        values["sha256"]});

    if (save_to_archive) {
      archived_lines.push_back(line);
    }
  }
}

void scrapeCurrentLog(LogEntries& response, SantaDecisionType decision) {
  response.clear();

  std::ifstream log_file;
  log_file.open(kSantaLogPath);
  if (!log_file.is_open()) {
    return;
  }

  scrapeStream(log_file, response, false, decision);
  log_file.close();
}

bool scrapeCompressedSantaLog(std::string file_path,
                              LogEntries& response,
                              SantaDecisionType decision) {
  std::ifstream log_file(file_path, std::ios_base::in | std::ios_base::binary);
  if (!log_file.is_open()) {
    return false;
  }

  boost::iostreams::filtering_streambuf<boost::iostreams::input> in;
  in.push(boost::iostreams::gzip_decompressor());
  in.push(log_file);

  std::istream incoming(&in);
  scrapeStream(incoming, response, true, decision);

  log_file.close();
  return true;
}

bool newArchiveFileExists() {
  std::stringstream strstr;
  strstr << kSantaLogPath << "." << next_oldest_archive << ".gz";
  std::ifstream file(strstr.str(), std::ios_base::in | std::ios_base::binary);
  return file.is_open();
}

void processArchivedLines(LogEntries& response) {
  for (std::list<std::string>::const_iterator iter = archived_lines.begin();
       iter != archived_lines.end();
       ++iter) {
    std::map<std::string, std::string> values;
    extractValues(*iter, values);
    response.push_back({values["timestamp"],
                        values["path"],
                        values["reason"],
                        values["sha256"]});
  }
}

bool scrapeSantaLog(LogEntries& response, SantaDecisionType decision) {
  try {
    scrapeCurrentLog(response, decision);

    // if there are no new archived files, just process our stash
    if (!newArchiveFileExists()) {
      processArchivedLines(response);
      return true;
    }

    // rolling archive files--clear the stored archive and reprocess them all
    archived_lines.clear();
    for (unsigned int i = 0;; ++i) {
      next_oldest_archive = i;

      std::stringstream strstr;
      strstr << kSantaLogPath << "." << i << ".gz";
      if (!scrapeCompressedSantaLog(strstr.str(), response, decision)) {
        break;
      }
    }

    return true;

  } catch (const std::exception& e) {
    VLOG(1) << "Failed to read the Santa log files: " << e.what();
    return false;
  }
}

static int rulesCallback(void* context,
                         int argc,
                         char** argv,
                         char** azColName) {
  // clang-format off

  // Expected argc/argv format:
  //     shasum,           state,        type, custom_message
  //     shasum, white/blacklist, binary/cert, arbitrary text

  // clang-format on

  RuleEntries* rules = static_cast<RuleEntries*>(context);
  if (argc != 4) {
    return 0;
  }

  RuleEntry new_rule;
  new_rule.shasum = argv[0];
  new_rule.state = (argv[1][0] == '1') ? RuleEntry::State::Whitelist
                                       : RuleEntry::State::Blacklist;

  new_rule.type = (argv[2][0] == '1') ? RuleEntry::Type::Binary
                                      : RuleEntry::Type::Certificate;

  new_rule.custom_message = (argv[3] == nullptr) ? "" : argv[3];

  rules->push_back(std::move(new_rule));
  return 0;
}

bool collectSantaRules(RuleEntries& response) {
  response.clear();

  // make a copy of the rules db (santa keeps the db locked)
  std::ifstream src(kSantaDatabasePath, std::ios_base::binary);
  if (!src.is_open()) {
    VLOG(1) << "Failed to access the Santa rule database";
    return false;
  }

  std::ofstream dst(kTemporaryDatabasePath,
                    std::ios_base::binary | std::ios_base::trunc);

  if (!dst.is_open()) {
    VLOG(1) << "Failed to duplicate the Santa rule database";
    return false;
  }

  dst << src.rdbuf();
  src.close();
  dst.close();

  // Open the database copy and enumerate the rules
  sqlite3* db;
  int rc = sqlite3_open(kTemporaryDatabasePath.c_str(), &db);
  if (SQLITE_OK != rc) {
    VLOG(1) << "Failed to read Santa rule database";
    return false;
  }

  char* sqlite_error_message = nullptr;
  // Note: Santa calls its column 'custommsg', but following osquery convention
  // our column is called 'custom_message'.
  rc = sqlite3_exec(db,
                    "SELECT shasum, state, type, custommsg FROM rules;",
                    rulesCallback,
                    &response,
                    &sqlite_error_message);

  if (rc != SQLITE_OK) {
    VLOG(1) << "Failed to query the Santa rule database: "
            << (sqlite_error_message != nullptr ? sqlite_error_message : "");
  }

  if (sqlite_error_message != nullptr) {
    sqlite3_free(sqlite_error_message);
  }

  rc = sqlite3_close(db);
  if (rc != SQLITE_OK) {
    VLOG(1) << "Failed to close the Santa rule database";
  }
  return (rc == SQLITE_OK);
}

const char* getRuleTypeName(RuleEntry::Type type) {
  switch (type) {
  case RuleEntry::Type::Binary:
    return "binary";

  case RuleEntry::Type::Certificate:
    return "certificate";

  case RuleEntry::Type::Unknown:
  default:
    return "unknown";
  }
}

const char* getRuleStateName(RuleEntry::State state) {
  switch (state) {
  case RuleEntry::State::Whitelist:
    return "whitelist";

  case RuleEntry::State::Blacklist:
    return "blacklist";

  case RuleEntry::State::Unknown:
  default:
    return "unknown";
  }
}

RuleEntry::Type getTypeFromRuleName(const char* name) {
  std::string type_name(name);

  if (type_name == "certificate") {
    return RuleEntry::Type::Certificate;
  } else if (type_name == "binary") {
    return RuleEntry::Type::Binary;
  } else {
    return RuleEntry::Type::Unknown;
  }
}

RuleEntry::State getStateFromRuleName(const char* name) {
  std::string state_name(name);

  if (state_name == "blacklist") {
    return RuleEntry::State::Blacklist;
  } else if (state_name == "whitelist") {
    return RuleEntry::State::Whitelist;
  } else {
    return RuleEntry::State::Unknown;
  }
}
