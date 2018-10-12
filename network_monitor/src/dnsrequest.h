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

#include "packet.h"

namespace trailofbits {
class DNSRequest;

/// A reference to a DNSRequest object
using DNSRequestRef = std::shared_ptr<DNSRequest>;

/// Request opcode
enum DNSRequestOpcode {
  DNSRequestOpcode_StandardQuery = 0,
  DNSRequestOpcode_InverseQuery = 1,
  DNSRequestOpcode_ServerStatusRequest = 2
};

/// Server response code
enum DNSResponseCode {
  DNSResponseCode_Success = 0,
  DNSResponseCode_FormatError = 1,
  DNSResponseCode_ServerFailure = 2,
  DNSResponseCode_NameError = 3,
  DNSResponseCode_NotImplemented = 4,
  DNSResponseCode_Refused = 5
};

/// A DNSRequest object
class DNSRequest final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use ::create() instead
  DNSRequest(PacketRef packet_ref);

  /// Attempts to parse the resource records
  void parseResourceRecords();

 public:
  /// Crates a new DNSRequest object from the given packet
  static osquery::Status create(DNSRequestRef& ref, PacketRef packet_ref);

  /// Appends a new packet to this request in order to complete it. Only
  /// works if the reequest is truncated and the identifiers match
  osquery::Status appendPacket(PacketRef packet_ref);

  /// Returns the DNS request identifier, used to join fragmented requests
  /// and match answer/response
  std::uint16_t requestIdentifier() const;

  /// Returns true if this is a response, or false otherwise
  bool isQuestion() const;

  /// Returns the request opcode
  DNSRequestOpcode requestOpcode() const;

  /// Returns true if the responding name server is anauthority for the
  /// domain name in question section
  bool isAuthoritativeAnswer() const;

  /// Returns true if the request is truncated
  bool isTruncated() const;

  /// Returns true if recursion was requested
  bool recursionRequested() const;

  /// Returns true if recursion is available
  bool recursionAvailable() const;

  /// Returns the server response code
  DNSResponseCode responseCode() const;

  /// Returns the amount of items in the question section
  std::uint16_t questionCount() const;

  /// Returns the amount of resource records in the answer section
  std::uint16_t answerCount() const;

  /// Return the amount of server resource records in the authority records
  /// section
  std::uint16_t authorityRecordCount() const;

  /// The amount of resource records in the additional records section
  std::uint16_t additionalRecordCount() const;

  /// Returns the IP protocol
  IPProtocol ipProtocol() const;

  /// Eithert TCP or UDP
  Protocol protocol() const;

  /// Returns the timestamp
  std::time_t timestamp() const;

  /// Returns the source address
  IPAddress sourceAddress() const;

  /// Returns the destination address
  IPAddress destinationAddress() const;

  /// Attempts to extract the DNS request identifier from the given packet
  static osquery::Status extractIdentifierFromPacket(std::uint16_t& identifier,
                                                     PacketRef packet_ref);
};
} // namespace trailofbits
