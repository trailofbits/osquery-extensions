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

#include "packetreader.h"

#include <stack>

namespace trailofbits {
/// Private class data for the PacketReaderException class
struct PacketReaderException::PrivateData final {
  /// Packet timestamp
  std::time_t packet_timestamp{0U};

  /// Offset at which the operation has failed
  std::size_t read_offset{0U};

  /// How many bytes the reader was attempting to acquire when the error
  /// occurred
  std::size_t read_size{0U};

  /// Error message returned by the what() method
  std::string error_message;
};

PacketReaderException::PacketReaderException(std::time_t packet_timestamp,
                                             std::size_t read_offset,
                                             std::size_t read_size)
    : d(new PrivateData) {
  d->packet_timestamp = packet_timestamp;
  d->read_offset = read_offset;
  d->read_size = read_size;

  std::stringstream buffer;
  buffer << "Read error on packet '" << packet_timestamp << "' at offset "
         << read_offset << " when attempting to read " << read_size << " bytes";
  d->error_message = buffer.str();
}

const char* PacketReaderException::what() const noexcept {
  return d->error_message.c_str();
}

std::size_t PacketReaderException::offset() const {
  return d->read_offset;
}

std::size_t PacketReaderException::size() const {
  return d->read_size;
}

/// Private class data for the PacketReader class
struct PacketReader::PrivateData final {
  /// Data source
  PacketRef packet_ref;

  /// Read offset
  std::size_t read_offset{0U};

  /// Offset stack, used by pushOffset and popOffset
  std::stack<std::size_t> offset_stack;
};

PacketReader::PacketReader(PacketRef& packet_ref) : d(new PrivateData) {
  d->packet_ref = packet_ref;
}

osquery::Status PacketReader::create(PacketReaderRef& ref,
                                     PacketRef packet_ref) {
  ref.reset();

  try {
    auto ptr = new PacketReader(packet_ref);
    ref.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

PacketReader::~PacketReader() {}

void PacketReader::setOffset(std::size_t offset) {
  d->read_offset = offset;
}

std::size_t PacketReader::offset() const {
  return d->read_offset;
}

void PacketReader::pushOffset() {
  d->offset_stack.push(d->read_offset);
}

void PacketReader::popOffset() {
  if (d->offset_stack.empty()) {
    return;
  }

  d->read_offset = d->offset_stack.top();
  d->offset_stack.pop();
}

void PacketReader::readBuffer(std::uint8_t* buffer, std::size_t size) {
  if (buffer == nullptr) {
    throw PacketReaderException(
        d->packet_ref->timestamp(), d->read_offset, size);
  }

  if (size == 0) {
    return;
  }

  const auto& source_buffer = d->packet_ref->data();
  if (d->read_offset + size >= source_buffer.size()) {
    throw PacketReaderException(
        d->packet_ref->timestamp(), d->read_offset, size);
  }

  std::memcpy(buffer, source_buffer.data() + d->read_offset, size);
  d->read_offset += size;
}

std::string PacketReader::pascalString() {
  std::uint8_t string_length;
  read(string_length);

  std::string buffer;
  buffer.resize(string_length);

  readBuffer(reinterpret_cast<std::uint8_t*>(&buffer[0]), string_length);

  return buffer;
}

std::string PacketReader::nullTerminatedString() {
  std::string buffer;

  while (true) {
    std::uint8_t current_byte = 0U;
    read(current_byte);

    if (current_byte == 0U) {
      break;
    }

    buffer.push_back(static_cast<char>(current_byte));
  }

  return buffer;
}
} // namespace trailofbits
