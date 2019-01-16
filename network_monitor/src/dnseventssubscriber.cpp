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

#include "dnseventssubscriber.h"

namespace trailofbits {
// clang-format off
BEGIN_TABLE(dns_events)
  // Event time, equal to the capture time
  TABLE_COLUMN(event_time, osquery::TEXT_TYPE)

  // Source and destination hosts
  TABLE_COLUMN(source_address, osquery::TEXT_TYPE)
  TABLE_COLUMN(destination_address, osquery::TEXT_TYPE)

  // DNS header information
  TABLE_COLUMN(protocol, osquery::TEXT_TYPE)
  TABLE_COLUMN(truncated, osquery::TEXT_TYPE)
  TABLE_COLUMN(id, osquery::TEXT_TYPE)
  TABLE_COLUMN(type, osquery::TEXT_TYPE)

  // Columns used by both queries and responses
  TABLE_COLUMN(record_type, osquery::TEXT_TYPE)
  TABLE_COLUMN(record_class, osquery::TEXT_TYPE)
  TABLE_COLUMN(record_name, osquery::TEXT_TYPE)

  // Columns only used by responses
  TABLE_COLUMN(ttl, osquery::TEXT_TYPE)
  TABLE_COLUMN(record_data, osquery::TEXT_TYPE)
END_TABLE(dns_events)
// clang-format on

namespace {
const char* getDnsRecordType(pcpp::DnsType type) {
  switch (type) {
  case pcpp::DNS_TYPE_A:
    return "A";
  case pcpp::DNS_TYPE_NS:
    return "NS";
  case pcpp::DNS_TYPE_MD:
    return "MD";
  case pcpp::DNS_TYPE_MF:
    return "MF";
  case pcpp::DNS_TYPE_CNAME:
    return "CNAME";
  case pcpp::DNS_TYPE_SOA:
    return "SOA";
  case pcpp::DNS_TYPE_MB:
    return "MB";
  case pcpp::DNS_TYPE_MG:
    return "MG";
  case pcpp::DNS_TYPE_MR:
    return "MR";
  case pcpp::DNS_TYPE_NULL_R:
    return "NULL_R";
  case pcpp::DNS_TYPE_WKS:
    return "WKS";
  case pcpp::DNS_TYPE_PTR:
    return "PTR";
  case pcpp::DNS_TYPE_HINFO:
    return "HINFO";
  case pcpp::DNS_TYPE_MINFO:
    return "MINFO";
  case pcpp::DNS_TYPE_MX:
    return "MX";
  case pcpp::DNS_TYPE_TXT:
    return "TXT";
  case pcpp::DNS_TYPE_RP:
    return "RP";
  case pcpp::DNS_TYPE_AFSDB:
    return "AFSDB";
  case pcpp::DNS_TYPE_X25:
    return "X25";
  case pcpp::DNS_TYPE_ISDN:
    return "ISDN";
  case pcpp::DNS_TYPE_RT:
    return "RT";
  case pcpp::DNS_TYPE_NSAP:
    return "NSAP";
  case pcpp::DNS_TYPE_NSAP_PTR:
    return "NSAP_PTR";
  case pcpp::DNS_TYPE_SIG:
    return "SIG";
  case pcpp::DNS_TYPE_KEY:
    return "KEY";
  case pcpp::DNS_TYPE_PX:
    return "PX";
  case pcpp::DNS_TYPE_GPOS:
    return "GPOS";
  case pcpp::DNS_TYPE_AAAA:
    return "AAAA";
  case pcpp::DNS_TYPE_LOC:
    return "LOC";
  case pcpp::DNS_TYPE_NXT:
    return "NXT";
  case pcpp::DNS_TYPE_EID:
    return "EID";
  case pcpp::DNS_TYPE_NIMLOC:
    return "NIMLOC";
  case pcpp::DNS_TYPE_SRV:
    return "SRV";
  case pcpp::DNS_TYPE_ATMA:
    return "ATMA";
  case pcpp::DNS_TYPE_NAPTR:
    return "NAPTR";
  case pcpp::DNS_TYPE_KX:
    return "KX";
  case pcpp::DNS_TYPE_CERT:
    return "CERT";
  case pcpp::DNS_TYPE_A6:
    return "A6";
  case pcpp::DNS_TYPE_DNAM:
    return "DNAM";
  case pcpp::DNS_TYPE_SINK:
    return "SINK";
  case pcpp::DNS_TYPE_OPT:
    return "OPT";
  case pcpp::DNS_TYPE_APL:
    return "APL";
  case pcpp::DNS_TYPE_DS:
    return "DS";
  case pcpp::DNS_TYPE_SSHFP:
    return "SSHFP";
  case pcpp::DNS_TYPE_IPSECKEY:
    return "IPSECKEY";
  case pcpp::DNS_TYPE_RRSIG:
    return "RRSIG";
  case pcpp::DNS_TYPE_NSEC:
    return "NSEC";
  case pcpp::DNS_TYPE_DNSKEY:
    return "DNSKEY";
  case pcpp::DNS_TYPE_DHCID:
    return "DHCID";
  case pcpp::DNS_TYPE_NSEC3:
    return "NSEC3";
  case pcpp::DNS_TYPE_NSEC3PARAM:
    return "NSEC3PARAM";
  case pcpp::DNS_TYPE_ALL:
    return "ALL";
  }
}

const char* getDnsClass(pcpp::DnsClass dns_class) {
  switch (dns_class) {
  case pcpp::DNS_CLASS_IN:
    return "IN";
  case pcpp::DNS_CLASS_IN_QU:
    return "IN_QU";
  case pcpp::DNS_CLASS_CH:
    return "CH";
  case pcpp::DNS_CLASS_HS:
    return "HS";
  case pcpp::DNS_CLASS_ANY:
    return "ANY";
  }
}

const char* responseCodeToString(std::uint16_t response_code) {
  switch (response_code) {
  case 0:
    return "NOERROR";
  case 1:
    return "FORMERR";
  case 2:
    return "SERVFAIL";
  case 3:
    return "NXDOMAIN";
  case 4:
    return "NOTIMP";
  case 5:
    return "REFUSED";
  case 6:
    return "YXDOMAIN";
  case 7:
    return "XRRSET";
  case 8:
    return "NOTAUTH";
  case 9:
    return "NOTZONE";
  }

  return "UNKNOWN ERROR";
}
} // namespace

osquery::Status DNSEventsSubscriber::create(IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new DNSEventsSubscriber();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status DNSEventsSubscriber::initialize() noexcept {
  return osquery::Status(0);
}

void DNSEventsSubscriber::release() noexcept {}

osquery::Status DNSEventsSubscriber::configure(
    DNSEventsPublisher::SubscriptionContextRef subscription_context,
    const json11::Json& configuration) noexcept {
  static_cast<void>(subscription_context);
  static_cast<void>(configuration);

  return osquery::Status(0);
}

osquery::Status DNSEventsSubscriber::callback(
    osquery::QueryData& new_events,
    DNSEventsPublisher::SubscriptionContextRef,
    DNSEventsPublisher::EventContextRef event_context) {
  for (const auto& event : event_context->event_list) {
    osquery::Row row = {};

    row["event_time"] = std::to_string(event.event_time.tv_sec);

    row["source_address"] = event.source_address;
    row["destination_address"] = event.destination_address;

    row["id"] = std::to_string(event.id);
    if (event.protocol == pcpp::UDP) {
      row["protocol"] = "udp";
      row["truncated"] = event.truncated ? "1" : "0";
    } else {
      row["protocol"] = "tcp";
      row["truncated"] = "0";
    }

    if (event.type == DnsEvent::Type::Query) {
      row["type"] = "query";

      for (const auto& question_item : event.question) {
        row["record_type"] = getDnsRecordType(question_item.record_type);
        row["record_class"] = getDnsClass(question_item.record_class);
        row["record_name"] = question_item.record_name;

        new_events.push_back(row);
      }

    } else {
      row["type"] = "response";

      if (event.answer.size() > 0) {
        for (const auto& answer_item : event.answer) {
          row["record_type"] = getDnsRecordType(answer_item.record_type);
          row["record_class"] = getDnsClass(answer_item.record_class);
          row["record_name"] = answer_item.record_name;

          row["ttl"] = std::to_string(answer_item.ttl);
          row["record_data"] = answer_item.record_data;

          new_events.push_back(row);
        }
      } else {
        /*
         * There aren't any answer records; either it's a response with an
         * error, or an empty response (if there's no IPv6 record for instance)
         */
        if (event.responde_code != 0) {
          row["record_type"] = "FAILURE";
          row["record_data"] = responseCodeToString(event.responde_code);
        }
        new_events.push_back(row);
      }
    }
  }

  return osquery::Status(0);
}
} // namespace trailofbits
