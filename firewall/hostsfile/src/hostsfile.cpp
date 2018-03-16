#include "hostsfile.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>

namespace trailofbits {
const std::string hosts_file_path = "/etc/hosts";
const std::string temporary_hosts_file_path = "/etc/hosts.osquery-fwctl.tmp";

struct HostsFile::PrivateData final {
  std::mutex mutex;
};

HostsFile::Status HostsFile::create(std::unique_ptr<IHostsFile>& obj) {
  try {
    auto ptr = new HostsFile();
    obj.reset(ptr);

    return Status(true);

  } catch (const std::bad_alloc&) {
    return Status(false, Detail::MemoryAllocationError);

  } catch (const Status& status) {
    return status;
  }
}

HostsFile::~HostsFile() {}

HostsFile::Status HostsFile::addHost(const std::string& domain,
                                     const std::string& address) {
  std::lock_guard<std::mutex> lock(d->mutex);

  HostsFileData data;
  if (!ReadHostsFile(data)) {
    return Status(false);
  }

  for (const auto& pair : data) {
    const auto domain_list = pair.second;

    for (const auto& dom : domain_list) {
      if (dom == domain) {
        return Status(false, Detail::AlreadyExists);
      }
    }
  }

  if (!CopyFile_(hosts_file_path, temporary_hosts_file_path)) {
    return Status(false, Detail::IOError);
  }

  std::fstream temp_file(temporary_hosts_file_path,
                         std::fstream::out | std::fstream::app);
  if (!temp_file) {
    return Status(false, Detail::IOError);
  }

  temp_file << "\n" << address << "\t" << domain;
  if (!temp_file) {
    return Status(false, Detail::IOError);
  }

  temp_file.close();

  if (std::rename(temporary_hosts_file_path.data(), hosts_file_path.data()) !=
      0) {
    return Status(false, Detail::IOError);
  }

  return Status(true);
}

HostsFile::Status HostsFile::removeHost(const std::string& domain) {
  std::ifstream src(hosts_file_path);
  std::fstream dst(temporary_hosts_file_path, std::fstream::out);
  if (!src || !dst) {
    return Status(false, Detail::IOError);
  }

  std::string line;
  std::string current_address;
  std::set<std::string> current_domain_list;
  bool found = false;

  while (true) {
    std::getline(src, line);

    bool skip_line = false;

    if (ParseHostsFileLine(current_address, current_domain_list, line)) {
      auto it = current_domain_list.find(domain);
      if (it != current_domain_list.end()) {
        found = true;
        current_domain_list.erase(it);

        if (current_domain_list.empty()) {
          skip_line = true;

        } else {
          std::stringstream new_line;

          new_line << current_address << "\t";
          for (const auto& current_domain : current_domain_list) {
            new_line << current_domain << " ";
          }

          line = new_line.str();
        }
      }
    }

    if (skip_line) {
      if (dst.tellp() > 0) {
        dst.seekp(-1, std::ios_base::cur);
      }

    } else {
      dst << line << (line.find('\n') == std::string::npos ? "\n" : "");
      if (!dst) {
        return Status(false, Detail::IOError);
      }
    }

    if (src.eof()) {
      break;
    }
  }

  dst.close();
  src.close();

  if (std::rename(temporary_hosts_file_path.data(), hosts_file_path.data()) !=
      0) {
    return Status(false, Detail::IOError);
  }

  if (!found) {
    return Status(false, Detail::NotFound);
  }

  return Status(true);
}

HostsFile::Status HostsFile::enumerateHosts(
    bool (*callback)(const std::string& domain,
                     const std::string& address,
                     void* user_defined),
    void* user_defined) {
  HostsFileData data;

  {
    std::lock_guard<std::mutex> lock(d->mutex);
    if (!ReadHostsFile(data)) {
      return Status(false);
    }
  }

  for (const auto& pair : data) {
    const auto& address = pair.first;
    const auto domain_list = pair.second;

    for (const auto& domain : domain_list) {
      if (!callback(domain, address, user_defined)) {
        break;
      }
    }
  }

  return Status(true);
}

HostsFile::HostsFile() : d(new PrivateData) {}

bool HostsFile::ReadHostsFile(HostsFileData& data) {
  data.clear();

  std::ifstream stream(hosts_file_path);
  if (!stream) {
    return false;
  }

  std::string line;

  while (true) {
    std::getline(stream, line);

    std::string address;
    std::set<std::string> domain_list;

    if (ParseHostsFileLine(address, domain_list, line)) {
      auto it = data.find(address);
      if (it == data.end()) {
        data.insert({address, std::move(domain_list)});

      } else {
        auto& existing_domain_list = it->second;
        existing_domain_list.insert(domain_list.begin(), domain_list.end());
      }
    }

    if (stream.eof()) {
      break;
    }
  }

  return true;
}

bool HostsFile::CopyFile_(const std::string& source_path,
                          const std::string& dest_path) {
  std::ifstream src;
  src.exceptions(std::ifstream::failbit | std::ifstream::badbit);

  std::ofstream dst;
  dst.exceptions(std::ifstream::failbit | std::ifstream::badbit);

  try {
    src.open(source_path, std::ios::binary);
    dst.open(dest_path, std::ios::binary);
    dst << src.rdbuf();

    dst.close();
    src.close();

    return true;

  } catch (...) {
    return false;
  }
}

bool HostsFile::ParseHostsFileLine(std::string& address,
                                   std::set<std::string>& domain_list,
                                   const std::string& line) {
  address.clear();
  domain_list.clear();

  enum class State {
    Start,
    IPAddress,
    IPAddressSeparator,
    Domain,
    DomainSeparator
  };

  auto state = State::Start;
  std::string current_domain;

  for (std::size_t i = 0U; i < line.size(); i++) {
    auto c = line[i];

    if (state == State::Start) {
      if (!std::isspace(static_cast<unsigned char>(c))) {
        if (c == '#') {
          break;
        }

        state = State::IPAddress;

        i--;
        continue;
      }
    }

    else if (state == State::IPAddress) {
      if (std::isspace(static_cast<unsigned char>(c))) {
        if (address.empty()) {
          return false;
        }

        state = State::IPAddressSeparator;

      } else {
        address.push_back(c);
      }
    }

    else if (state == State::IPAddressSeparator) {
      if (!std::isspace(static_cast<unsigned char>(c))) {
        if (c == '#') {
          break;
        }

        state = State::Domain;

        i--;
        continue;
      }
    }

    else if (state == State::Domain) {
      if (std::isspace(static_cast<unsigned char>(c))) {
        if (current_domain.empty()) {
          return false;
        }

        domain_list.insert(current_domain);
        current_domain.clear();

        state = State::DomainSeparator;

      } else {
        current_domain.push_back(c);
      }

    } else if (state == State::DomainSeparator) {
      if (!std::isspace(static_cast<unsigned char>(c))) {
        if (c == '#') {
          break;
        }

        state = State::Domain;

        i--;
        continue;

      } else if (c == '#') {
        break;
      }
    }
  }

  // We may still have a pending item if the line has been ended without a
  // newline
  if (state == State::Domain && !current_domain.empty()) {
    domain_list.insert(current_domain);
  }

  return (!address.empty() && !domain_list.empty());
}

HostsFile::Status CreateHostsFileObject(std::unique_ptr<IHostsFile>& obj) {
  return HostsFile::create(obj);
}
} // namespace trailofbits
