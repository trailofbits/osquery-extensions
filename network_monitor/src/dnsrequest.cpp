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
#include "packetreader.h"

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

/// Reads the request header
osquery::Status readRequestHeader(PacketReaderRef& reader,
                                  DNSRequestHeader& header) {
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

  } catch (const PacketReaderException& e) {
    return osquery::Status(1, e.what());
  }
}
} // namespace

/// Private class data
struct DNSRequest::PrivateData final {
  /// The raw DNS request header
  DNSRequestHeader header;
};

DNSRequest::DNSRequest(PacketRef packet_ref) {
  if (packet_ref->data().size() < sizeof(DNSRequestHeader)) {
    throw osquery::Status(1, "Invalid DNS header: buffer is too small");
  }

  PacketReaderRef reader;
  auto status = PacketReader::create(reader, packet_ref);
  if (!status.ok()) {
    throw status;
  }

  status = readRequestHeader(reader, d->header);
  if (!status.ok()) {
    throw status;
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

std::uint16_t DNSRequest::requestIdentifier() const {
  return d->header.id;
}

bool DNSRequest::isQuestion() const {
  return d->header.qr;
}

DNSRequestOpcode DNSRequest::requestOpcode() const {
  return d->header.opcode;
}

bool DNSRequest::isAuthoritativeAnswer() const {
  return d->header.aa;
}

bool DNSRequest::isTruncated() const {
  return d->header.tc;
}

bool DNSRequest::recursionRequested() const {
  return d->header.rd;
}

bool DNSRequest::recursionAvailable() const {
  return d->header.ra;
}

DNSResponseCode DNSRequest::responseCode() const {
  return d->header.rcode;
}

std::uint16_t DNSRequest::questionCount() const {
  return d->header.qdcount;
}

std::uint16_t DNSRequest::answerCount() const {
  return d->header.ancount;
}

std::uint16_t DNSRequest::authorityRecordCount() const {
  return d->header.nscount;
}

std::uint16_t DNSRequest::additionalRecordCount() const {
  return d->header.arcount;
}

osquery::Status DNSRequest::extractIdentifierFromPacket(
    std::uint16_t& identifier, PacketRef packet_ref) {
  identifier = 0U;

  PacketReaderRef reader;
  auto status = PacketReader::create(reader, packet_ref);
  if (!status.ok()) {
    return status;
  }

  try {
    reader->read(identifier);
    return osquery::Status(0);

  } catch (const PacketReaderException& e) {
    return osquery::Status(1, e.what());
  }
}
} // namespace trailofbits
