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

  static bool ParseHostsFileLine(std::string& address,
                                 std::set<std::string>& domain_list,
                                 const std::string& line);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

IHostsFile::Status CreateHostsFileObject(std::unique_ptr<IHostsFile>& obj);
} // namespace trailofbits
