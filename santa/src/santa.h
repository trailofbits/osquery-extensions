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

#include <list>
#include <string>

enum SantaDecisionType {
  kAllowed,
  kDenied,
};

struct LogEntry final {
  std::string timestamp;
  std::string application;
  std::string reason;
  std::string sha256;
};

struct RuleEntry final {
  enum class Type { Binary, Certificate, Unknown };
  enum class State { Whitelist, Blacklist, Unknown };

  Type type;
  State state;
  std::string shasum;
  std::string custom_message;
};

using LogEntries = std::list<LogEntry>;
using RuleEntries = std::list<RuleEntry>;

const char* getRuleTypeName(RuleEntry::Type type);
const char* getRuleStateName(RuleEntry::State state);

RuleEntry::Type getTypeFromRuleName(const char* name);
RuleEntry::State getStateFromRuleName(const char* name);

bool scrapeSantaLog(LogEntries& response, SantaDecisionType decision);
bool collectSantaRules(RuleEntries& response);
