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

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <map>

#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include <sqlite3.h>

#include "santa.h"

const std::string LOG_PATH = "/var/db/santa/santa.log";
const std::string PREFACE = "santad: ";

const std::string RULES_PATH = "/var/db/santa/rules.db";
const std::string TEMP_RULES_PATH = "/tmp/rules.db";

void extractValues(std::string line, std::map<std::string, std::string>& values)
{
  //extract timestamp
  size_t timestamp_start = line.find("[");
  size_t timestamp_end = line.find("]");
  if (timestamp_start != std::string::npos && timestamp_end != std::string::npos && timestamp_start != timestamp_end) {
    values["timestamp"] = line.substr(timestamp_start + 1, timestamp_end - timestamp_start - 1);
  }

  //extract key=value pairs after the preface
  size_t key_pos = line.find(PREFACE);
  if (key_pos == std::string::npos) {
    return;
  }
  key_pos += PREFACE.length();
  size_t key_end, val_pos, val_end;
  while ((key_end = line.find('=', key_pos)) != std::string::npos) {
    if((val_pos = line.find_first_not_of("=", key_end)) == std::string::npos) {
      break;
    }

    val_end = line.find('|', val_pos);
    values.emplace(line.substr(key_pos, key_end - key_pos), line.substr(val_pos, val_end - val_pos));

    key_pos = val_end;
    if (key_pos != std::string::npos)
      ++key_pos;
  }
}

void scrapeStream(std::istream &incoming, LogEntries &response) {
  std::string line;
  while (std::getline(incoming, line))
  {
    //explicitly filter to only include DENY events
    if (line.find("decision=DENY") == std::string::npos) {
      continue;
    }

    std::map<std::string, std::string> values;
    extractValues(line, values);
    response.push_back({values["timestamp"], values["path"], values["reason"]});
  }
}


void scrapeCurrentLog(LogEntries& response) {
  std::ifstream log_file;
  log_file.open(LOG_PATH);
  if (!log_file.is_open()) {
    return;
  }

  scrapeStream(log_file, response);

  log_file.close();
}

bool scrapeCompressedSantaLog(std::string file_path, LogEntries& response)
{
  std::ifstream log_file(file_path, std::ios_base::in | std::ios_base::binary);
  if (!log_file.is_open()) {
    return false;
  }
  boost::iostreams::filtering_streambuf<boost::iostreams::input> in;
  in.push(boost::iostreams::gzip_decompressor());
  in.push(log_file);
  std::istream incoming(&in);

  scrapeStream(incoming, response);

  log_file.close();
  return true;
}

void scrapeSantaLog(LogEntries& response)
{
  scrapeCurrentLog(response);

  for (unsigned int i = 0; ; ++i) {
    std::stringstream strstr;
    strstr << LOG_PATH << "." << i << ".gz";
    if (!scrapeCompressedSantaLog(strstr.str(), response)) {
      break;
    }
  }
}

static int rulesCallback(void *context, int argc, char **argv, char **azColName) {
  RuleEntries *rules = static_cast<RuleEntries*>(context);
  if (argc == 3) {
    rules->push_back({std::string(argv[0]), std::string(argv[1]), std::string(argv[2])});
  }
  return 0;
}

void collectSantaRules(RuleEntries& response) {
  //make a copy of the rules db (santa keeps the db locked)
  std::ifstream src(RULES_PATH, std::ios_base::binary);
  if (!src.is_open()) {
    response.push_back({"error", "failed to open rules.db", ""});
    return;
  }
  std::ofstream dst(TEMP_RULES_PATH, std::ios_base::binary | std::ios_base::trunc);
  if (!dst.is_open()) {
    response.push_back({"error", "failed to open /tmp/rules.db", ""});
    return;
  }

  dst << src.rdbuf();
  src.close();
  dst.close();

  sqlite3 *db;
  int rc = sqlite3_open(TEMP_RULES_PATH.c_str(), &db);
  if (0 != rc) {
    //failed to open the database
    response.push_back({"error", "failed to open database", ""});
    return;
  }

  char *zErrorMessage = 0;
  rc = sqlite3_exec(db, "SELECT shasum, state, type FROM rules;", rulesCallback, &response, &zErrorMessage);
  if (rc != SQLITE_OK) {
    sqlite3_free(zErrorMessage);
    response.push_back({"error", "failed to execute query", ""});
  }

  sqlite3_close(db);
}
