/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include "utils.h"

#import <Foundation/Foundation.h>
#import <Foundation/NSProcessInfo.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IONetworkInterface.h>

#include <iomanip>
#include <sstream>

namespace {
struct IORegistryEntryDeleter final {
  using pointer = io_registry_entry_t;

  void operator()(pointer p) {
    IOObjectRelease(p);
  }
};

struct CFStringRefDeleter final {
  using pointer = CFStringRef;

  void operator()(pointer p) {
    CFRelease(p);
  }
};

bool getRegistryPropertyAsString(std::string& property_value,
                                 io_registry_entry_t registry,
                                 const std::string& property_name) {
  property_value.clear();

  std::unique_ptr<CFStringRef, CFStringRefDeleter> cfstring_property_name(
      CFStringCreateWithCStringNoCopy(nullptr,
                                      property_name.data(),
                                      kCFStringEncodingMacRoman,
                                      kCFAllocatorNull));

  std::unique_ptr<CFStringRef, CFStringRefDeleter> property;
  bool is_string = false;

  {
    CFStringRef p = static_cast<CFStringRef>(
        IORegistryEntryCreateCFProperty(registry,
                                        cfstring_property_name.get(),
                                        kCFAllocatorDefault,
                                        kNilOptions));

    if (p == nullptr) {
      return false;
    }

    property.reset(p);
    if (CFGetTypeID(property.get()) == CFDataGetTypeID()) {
      is_string = false;
    } else if (CFGetTypeID(property.get()) == CFStringGetTypeID()) {
      is_string = true;
    } else {
      return false;
    }
  }

  if (is_string) {
    auto string_ref = reinterpret_cast<CFStringRef>(property.get());
    std::size_t string_length = CFStringGetLength(string_ref);

    property_value.resize(string_length);

    CFStringGetCharacters(string_ref,
                          CFRangeMake(0U, string_length),
                          reinterpret_cast<UniChar*>(&property_value[0]));

  } else {
    auto data_ref = reinterpret_cast<CFDataRef>(property.get());
    auto buffer = reinterpret_cast<const char*>(CFDataGetBytePtr(data_ref));

    std::size_t buffer_length = CFDataGetLength(data_ref);
    property_value = std::string(buffer, buffer_length);
  }

  return true;
}
} // namespace

std::string getSha256Hash(const std::uint8_t* buffer, std::size_t length) {
  SHA256_CTX context;
  SHA256_Init(&context);

  SHA256_Update(&context, buffer, length);

  std::uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256_Final(digest, &context);

  std::stringstream string_digest;
  for (std::size_t i = 0U; i < SHA256_DIGEST_LENGTH; i++) {
    string_digest << std::setw(2) << std::setfill('0') << std::hex
                  << static_cast<int>(digest[i]);
  }

  return string_digest.str();
}

void getEFIVersion(std::string& version) {
  io_registry_entry_t registry = MACH_PORT_NULL;

  try {
    registry =
        IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/rom");
    if (registry == MACH_PORT_NULL) {
      throw std::runtime_error("Failed to open the rom registry entry");
    }

    if (!getRegistryPropertyAsString(version, registry, "version")) {
      throw std::runtime_error("Failed to acquire the logic board id");
    }

    IOObjectRelease(registry);

  } catch (const std::exception& e) {
    if (registry != MACH_PORT_NULL) {
      IOObjectRelease(registry);
    }

    throw;
  }
}

void getSMCVersion(std::string& version) {
  io_registry_entry_t registry = MACH_PORT_NULL;

  try {
    registry = IOServiceGetMatchingService(kIOMasterPortDefault,
                                           IOServiceMatching("AppleSMC"));

    if (registry == MACH_PORT_NULL) {
      throw std::runtime_error("Failed to open the AppleSMC registry entry");
    }

    if (!getRegistryPropertyAsString(version, registry, "smc-version")) {
      throw std::runtime_error("Failed to acquire the logic board id");
    }

    IOObjectRelease(registry);

  } catch (const std::exception& e) {
    if (registry != MACH_PORT_NULL) {
      IOObjectRelease(registry);
    }

    throw;
  }
}

void getHardwareModel(std::string& model, io_registry_entry_t registry) {
  if (!getRegistryPropertyAsString(model, registry, "model")) {
    throw std::runtime_error("Failed to acquire the hardware model");
  }

  if (model.find("Mac") != 0) {
    throw std::runtime_error(std::string("Unsupported model type: ") + model);
  }
}

void getOSVersion(std::string& version, std::string& build) {
  auto system_version_dict =
      [NSDictionary dictionaryWithContentsOfFile:
                        @"/System/Library/CoreServices/SystemVersion.plist"];

  NSString* system_version =
      [system_version_dict objectForKey:@"ProductVersion"];

  NSString* build_number =
      [system_version_dict objectForKey:@"ProductBuildVersion"];

  version = [system_version UTF8String];
  build = [build_number UTF8String];
}

void getBoardID(std::string& board_id, io_registry_entry_t registry) {
  if (!getRegistryPropertyAsString(board_id, registry, "board-id")) {
    throw std::runtime_error("Failed to acquire the logic board id");
  }

  if (board_id.find("Mac-") != 0) {
    throw std::runtime_error(std::string("Unsupported logic board id: ") +
                             board_id);
  }
}

void getMACAddress(std::string& mac) {
  CFMutableDictionaryRef eth_service_dict =
      IOServiceMatching(kIOEthernetInterfaceClass);

  if (eth_service_dict == nullptr) {
    throw std::runtime_error(
        "Failed to access the IOEthernetInterfaceClass dictionary");
  }

  CFMutableDictionaryRef helper_dict =
      CFDictionaryCreateMutable(kCFAllocatorDefault,
                                0,
                                &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks);

  if (helper_dict == nullptr) {
    throw std::runtime_error("Failed to create the dictionary");
  }

  CFDictionarySetValue(helper_dict, CFSTR(kIOPrimaryInterface), kCFBooleanTrue);

  CFDictionarySetValue(
      eth_service_dict, CFSTR(kIOPropertyMatchKey), helper_dict);

  CFRelease(helper_dict);

  io_iterator_t property_iterator;
  if (IOServiceGetMatchingServices(kIOMasterPortDefault,
                                   eth_service_dict,
                                   &property_iterator) != KERN_SUCCESS) {
    throw std::runtime_error("Failed to initialize the property iterator");
  }

  io_object_t it;
  UInt8 mac_address[kIOEthernetAddressSize];

  while ((it = IOIteratorNext(property_iterator))) {
    io_object_t controller_service;
    if (IORegistryEntryGetParentEntry(
            it, kIOServicePlane, &controller_service) != KERN_SUCCESS) {
      continue;
    }

    CFTypeRef mac_address_property = IORegistryEntryCreateCFProperty(
        controller_service, CFSTR(kIOMACAddress), kCFAllocatorDefault, 0);
    if (mac_address_property == nullptr) {
      IOObjectRelease(controller_service);
      continue;
    }

    CFDataGetBytes(static_cast<CFDataRef>(mac_address_property),
                   CFRangeMake(0, kIOEthernetAddressSize),
                   mac_address);

    CFRelease(mac_address_property);
    IOObjectRelease(controller_service);

    break;
  }

  IOObjectRelease(it);
  IOObjectRelease(property_iterator);

  std::stringstream buffer;
  buffer << "0x";

  for (std::size_t i = 0; i < kIOEthernetAddressSize; i++) {
    buffer << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned int>(mac_address[i]);
  }

  mac = buffer.str();
}

void getHostUUID(std::string& uuid, io_registry_entry_t registry) {
  if (!getRegistryPropertyAsString(uuid, registry, "IOPlatformUUID")) {
    throw std::runtime_error("Failed to acquire the platform UUID");
  }
}

void getSystemInformation(SystemInformation& system_info) {
  getOSVersion(system_info.os_ver, system_info.build_num);
  getMACAddress(system_info.mac_addr);
  getEFIVersion(system_info.rom_ver);
  getSMCVersion(system_info.smc_ver);

  {
    std::unique_ptr<io_registry_entry_t, IORegistryEntryDeleter> registry(
        IOServiceGetMatchingService(
            kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice")));

    if (registry.get() == MACH_PORT_NULL) {
      throw std::runtime_error(
          "Failed to open the IOPlatformExpertDevice registry entry");
    }

    getBoardID(system_info.board_id, registry.get());
    getHardwareModel(system_info.hw_ver, registry.get());
    getHostUUID(system_info.sys_uuid, registry.get());
  }
}
