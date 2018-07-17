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

#include <boost/noncopyable.hpp>

#include <memory>
#include <string>

#include <trailofbits/istatus.h>

namespace trailofbits {
class IHostsFile : private boost::noncopyable {
 public:
  enum class Detail {
    Undetermined,
    MemoryAllocationError,
    AlreadyExists,
    NotFound,
    IOError
  };

  using Status = IStatus<Detail>;

  virtual ~IHostsFile() = default;

  virtual Status addHost(const std::string& domain,
                         const std::string& address) = 0;

  virtual Status removeHost(const std::string& domain) = 0;

  virtual Status enumerateHosts(bool (*callback)(const std::string& domain,
                                                 const std::string& address,
                                                 void* user_defined),
                                void* user_defined) = 0;
};

IHostsFile::Status CreateHostsFileObject(std::unique_ptr<IHostsFile>& obj);
} // namespace trailofbits
