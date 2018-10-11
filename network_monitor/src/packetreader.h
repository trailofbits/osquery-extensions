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

#include <memory>

#include <osquery/status.h>

#include "packet.h"

namespace trailofbits {
/// This class is used to emit exceptions when a read on a Packet fails
class PacketReaderException final : public std::exception {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

 public:
  /// Constructor
  PacketReaderException(std::time_t packet_timestamp,
                        std::size_t read_offset,
                        std::size_t read_size);

  /// Returns the error description
  virtual const char* what() const noexcept override;

  /// Returns the offset that the user was attempting to read
  std::size_t offset() const;

  /// Returns the size of the read operation
  std::size_t size() const;
};

class PacketReader;

/// A reference to a PacketReader object
using PacketReaderRef = std::unique_ptr<PacketReader>;

/// A helper class used to securely read data from a Packet
class PacketReader final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use ::create() instead
  PacketReader(PacketRef& packet_ref);

 public:
  /// Factory method
  static osquery::Status create(PacketReaderRef& ref, PacketRef packet_ref);

  /// Destructor
  ~PacketReader();

  /// Sets the buffer offset to the given value
  void setOffset(std::size_t offset);

  /// Returns the current buffer offset
  std::size_t offset() const;

  /// Saves the current buffer offset into the stack
  void pushOffset();

  /// Restores the previously pushed buffer offset from the stack
  void popOffset();

  /// Reads the specified amount of bytes in the given buffer
  void readBuffer(std::uint8_t* buffer, std::size_t size);

  /// Reads a Pascal-style string (i.e.: an array of characters prefixed with a
  /// length byte)
  std::string pascalString();

  /// Reads a null-terminated string
  std::string nullTerminatedString();

  /// Generic type reader
  template <typename T>
  void read(T& destination) {
    static_assert(
        std::is_standard_layout<T>::value && std::is_trivial<T>::value,
        "Type must be POD");

    auto read_size = sizeof(destination);
    auto buffer = reinterpret_cast<std::uint8_t*>(&destination);

    readBuffer(buffer, read_size);
  }

  /// Disable the copy constructor
  PacketReader(const PacketReader& other) = delete;

  /// Disable the assignment operator
  PacketReader& operator=(const PacketReader& other) = delete;
};
} // namespace trailofbits
