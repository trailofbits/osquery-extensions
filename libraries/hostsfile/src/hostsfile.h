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

#include <trailofbits/ihostsfile.h>

#include <set>
#include <unordered_map>

namespace trailofbits {
using HostsFileData = std::unordered_map<std::string, std::set<std::string>>;

class HostsFile final : public IHostsFile {
 public:
  static Status create(std::unique_ptr<IHostsFile>& obj);
  virtual ~HostsFile();

  virtual Status addHost(const std::string& domain,
                         const std::string& address) override;

  virtual Status removeHost(const std::string& domain) override;

  virtual Status enumerateHosts(bool (*callback)(const std::string& domain,
                                                 const std::string& address,
                                                 void* user_defined),
                                void* user_defined) override;

 private:
  HostsFile();

  static bool ReadHostsFile(HostsFileData& data);

  static bool CopyFile_(const std::string& source_path,
                        const std::string& dest_path);
  static bool MoveFile_(const std::string& source_path,
                        const std::string& dest_path);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  static bool ParseHostsFileLine(std::string& address,
                                 std::set<std::string>& domain_list,
                                 const std::string& line);
};

IHostsFile::Status CreateHostsFileObject(std::unique_ptr<IHostsFile>& obj);
} // namespace trailofbits
