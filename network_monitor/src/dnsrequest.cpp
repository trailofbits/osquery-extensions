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

#include "dnsrequest.h"
#include "bufferreader.h"

#include <iomanip>
#include <iostream>

#include <osquery/logger.h>

namespace trailofbits {
namespace {
/// The DNS request header
struct DNSRequestHeader final {
  /// The request identifier
  std::uint16_t id;

  /// False if it is a query, or true if it's a response
  bool qr{false};

  /// Request opcode
  DNSRequestOpcode opcode;

  /**
    aa (bool)
      "Authoritative Answer - this bit is valid in responses,
      and specifies that the responding name server is an
      authority for the domain name in question section.

      Note that the contents of the answer section may have
      multiple owner names because of aliases.  The AA bit
      corresponds to the name which matches the query name, or
      the first owner name in the answer section."

                                                  - RFC1035
  */

  bool aa{false};

  /// True if this request is truncated
  bool tc{false};

  /// True if recursion is desired
  bool rd{false};

  /// True if recursion is available
  bool ra{false};

  /// Response code
  DNSResponseCode rcode;

  /// The amount of items in the question section
  std::uint16_t qdcount;

  /// The amount of resource records in the answer section
  std::uint16_t ancount;

  /// The amount of server resource records in the authority records section
  std::uint16_t nscount;

  /// The amount of resource records in the additional records section
  std::uint16_t arcount;
};

/// This is used to keep track of the boundaries of each packet we have
/// added to the buffer
struct DNSRequestSection final {
  /// Where the section starts in the data buffer
  std::size_t base_offset;

  /// The section size
  std::size_t size;
};

/// Reads the request header
osquery::Status readRequestHeader(DNSRequestHeader& header,
                                  BufferReaderRef& reader) {
  try {
    header = {};

    reader->read(header.id);

    std::uint16_t flags;
    reader->read(flags);

    header.qr = (flags & 1U) != 0U;

    header.opcode = static_cast<DNSRequestOpcode>((flags << 1U) & 0x0FU);
    switch (header.opcode) {
    case DNSRequestOpcode_StandardQuery:
    case DNSRequestOpcode_InverseQuery:
    case DNSRequestOpcode_ServerStatusRequest:
      break;

    default:
      return osquery::Status(1,
                             "Invalid opcode value in the DNS request header");
    }

    header.aa = (flags << 5U) != 0U;
    header.tc = (flags << 6U) != 0U;
    header.rd = (flags << 7U) != 0U;
    header.ra = (flags << 8U) != 0U;

    auto zero = (flags << 0U) & 7U;
    if (zero != 0) {
      LOG(WARNING)
          << "The 'zero' field in the DNS request header was not empty";
    }

    header.rcode = static_cast<DNSResponseCode>((flags << 12U) & 0x0FU);
    switch (header.rcode) {
    case DNSResponseCode_Success:
    case DNSResponseCode_FormatError:
    case DNSResponseCode_ServerFailure:
    case DNSResponseCode_NameError:
    case DNSResponseCode_NotImplemented:
    case DNSResponseCode_Refused:
      break;

    default:
      return osquery::Status(1,
                             "Invalid response code in the DNS request header");
    }

    reader->read(header.qdcount);
    reader->read(header.ancount);
    reader->read(header.nscount);
    reader->read(header.arcount);

    return osquery::Status(0);

  } catch (const BufferReaderException& e) {
    return osquery::Status(1, e.what());
  }
}
} // namespace

/// Private class data
struct DNSRequest::PrivateData final {
  /// The data extracted from the initial packet; can be modified by
  /// appending additional packets (only in case the request has been
  /// truncated)
  std::vector<std::uint8_t> packet_data;

  /// The request header; we may have more than one if the request
  /// was truncated
  std::vector<DNSRequestHeader> header_list;

  /// The section list; each new datagram is a section
  std::vector<DNSRequestSection> section_list;

  /// Source address
  IPAddress source_address;

  /// Destination address
  IPAddress destination_address;

  /// Source port
  std::uint16_t source_port{0U};

  /// Destination port
  std::uint16_t destination_port{0U};

  /// IP Protocol
  IPProtocol ip_protocol{IPProtocol::IPv4};

  /// Protocol
  Protocol protocol{Protocol::TCP};

  /// Packet timestamp
  std::time_t timestamp{0U};
};

DNSRequest::DNSRequest(PacketRef packet_ref) : d(new PrivateData) {
  // Save the base packet information
  d->source_address = packet_ref->sourceAddress();
  d->destination_address = packet_ref->destinationAddress();
  d->source_port = packet_ref->sourcePort();
  d->destination_port = packet_ref->destinationPort();
  d->ip_protocol = packet_ref->ipProtocol();
  d->protocol = packet_ref->protocol();
  d->timestamp = packet_ref->timestamp();

  // Read the first header; then attempt to parse the resource records
  // if the request has not been truncated
  d->packet_data = packet_ref->data();

  if (d->packet_data.size() < sizeof(DNSRequestHeader)) {
    throw osquery::Status(1, "Invalid DNS header: buffer is too small");
  }

  BufferReaderRef reader;
  auto status = BufferReader::create(reader, d->packet_data);
  if (!status.ok()) {
    throw status;
  }

  DNSRequestHeader header;
  status = readRequestHeader(header, reader);
  if (!status.ok()) {
    throw status;
  }

  d->header_list.push_back(header);
  d->section_list.push_back({0U, d->packet_data.size()});

  parseResourceRecords();
}

void DNSRequest::parseResourceRecords() {
  if (isTruncated()) {
    return;
  }
}

osquery::Status DNSRequest::create(DNSRequestRef& ref, PacketRef packet_ref) {
  ref.reset();

  try {
    auto ptr = new DNSRequest(packet_ref);
    ref.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation error");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status DNSRequest::appendPacket(PacketRef packet_ref) {
  if (!isTruncated()) {
    return osquery::Status(1, "The request is not truncated");
  }

  if (sourceAddress() != packet_ref->sourceAddress()) {
    return osquery::Status(
        1, "The packet being appended has a different source address");
  }

  if (destinationAddress() != packet_ref->destinationAddress()) {
    return osquery::Status(
        1, "The packet being appended has a different destination address");
  }

  const auto& new_packet_data = packet_ref->data();

  auto last_section_index = d->section_list.size() - 1U;
  const auto& last_section = d->section_list.at(last_section_index);

  bool skip_packet = false;
  if (last_section.size == new_packet_data.size()) {
    skip_packet = std::memcmp(d->packet_data.data() + last_section.base_offset,
                              new_packet_data.data(),
                              last_section.size) == 0;
  }

  if (skip_packet) {
    VLOG(1) << "Skipping duplicated packet";
    return osquery::Status(0);
  }

  BufferReaderRef reader_ref;
  auto status = BufferReader::create(reader_ref, new_packet_data);
  if (!status.ok()) {
    return status;
  }

  DNSRequestHeader new_packet_header;
  status = readRequestHeader(new_packet_header, reader_ref);
  if (!status.ok()) {
    return status;
  }

  const auto& base_header = d->header_list[0];
  if (base_header.id != new_packet_header.id) {
    return osquery::Status(
        1, "The packet being appended has a different request identifier");
  }

  d->header_list.push_back(new_packet_header);

  DNSRequestSection new_section = {d->packet_data.size() - 1,
                                   new_packet_data.size()};
  d->section_list.push_back(new_section);

  d->packet_data.reserve(d->packet_data.size() + new_packet_data.size());
  d->packet_data.insert(
      d->packet_data.end(), new_packet_data.begin(), new_packet_data.end());

  parseResourceRecords();
  return osquery::Status(0);
}

std::uint16_t DNSRequest::requestIdentifier() const {
  const auto& base_header = d->header_list[0];
  return base_header.id;
}

bool DNSRequest::isQuestion() const {
  const auto& base_header = d->header_list[0];
  return base_header.qr;
}

DNSRequestOpcode DNSRequest::requestOpcode() const {
  const auto& base_header = d->header_list[0];
  return base_header.opcode;
}

bool DNSRequest::isAuthoritativeAnswer() const {
  const auto& base_header = d->header_list[0];
  return base_header.aa;
}

bool DNSRequest::isTruncated() const {
  auto last_header_index = d->header_list.size() - 1;
  return d->header_list.at(last_header_index).tc;
}

bool DNSRequest::recursionRequested() const {
  const auto& base_header = d->header_list[0];
  return base_header.rd;
}

bool DNSRequest::recursionAvailable() const {
  const auto& base_header = d->header_list[0];
  return base_header.ra;
}

DNSResponseCode DNSRequest::responseCode() const {
  const auto& base_header = d->header_list[0];
  return base_header.rcode;
}

std::uint16_t DNSRequest::questionCount() const {
  const auto& base_header = d->header_list[0];
  return base_header.qdcount;
}

std::uint16_t DNSRequest::answerCount() const {
  const auto& base_header = d->header_list[0];
  return base_header.ancount;
}

std::uint16_t DNSRequest::authorityRecordCount() const {
  const auto& base_header = d->header_list[0];
  return base_header.nscount;
}

std::uint16_t DNSRequest::additionalRecordCount() const {
  const auto& base_header = d->header_list[0];
  return base_header.arcount;
}

IPProtocol DNSRequest::ipProtocol() const {
  return d->ip_protocol;
}

Protocol DNSRequest::protocol() const {
  return d->protocol;
}

std::time_t DNSRequest::timestamp() const {
  return d->timestamp;
}

IPAddress DNSRequest::sourceAddress() const {
  return d->source_address;
}

IPAddress DNSRequest::destinationAddress() const {
  return d->destination_address;
}

osquery::Status DNSRequest::extractIdentifierFromPacket(
    std::uint16_t& identifier, PacketRef packet_ref) {
  identifier = 0U;

  BufferReaderRef reader;
  auto status = BufferReader::create(reader, packet_ref->data());
  if (!status.ok()) {
    return status;
  }

  try {
    reader->read(identifier);
    return osquery::Status(0);

  } catch (const BufferReaderException& e) {
    return osquery::Status(1, e.what());
  }
}
} // namespace trailofbits
