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
