#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'bit-struct'

module Et
  module Frame
    class DtlsRecordHdr < BitStruct
      unsigned     :content_type,    8,  "Content Type"
      unsigned     :version,         16, "Version"
      unsigned     :epoch,           16, "Epoch"
      unsigned     :sequence_number, 48, "Sequence Number"
      unsigned     :fragment_length, 16, "Fragment Length"
      rest         :body,                "Body of message"
    end

    class DtlsAlertHdr < BitStruct
      unsigned     :level,            8, "Level"
      unsigned     :description,      8, "Description"
    end

    class DtlsHandshakeHdr < BitStruct
      unsigned     :msg_type,         8,  "message type"
      unsigned     :len,             24,  "length"
      unsigned     :message_seq,     16,  "message sequence number"
      unsigned     :fragment_offset, 24,  "fragment offset"
      unsigned     :fragment_length, 24,  "fragment length"
      rest         :body,                 "Body of message"
    end

    #class DtlsClientHelloHdr < BitStruct
    #  unsigned     :client_version,       16, "client version"
    #  hex_octets   :random,              256, "random"
    #  unsigned     :session_id_length,     8, "session id length"
    #  unsigned     :cookie_length,         8, "cookie length"
    #  unsigned     :cipher_suites_length, 16, "cipher suites length"
    #  unsigned     :cipher_suite,         16, "cipher suite"
    #  unsigned     :compression_methods_length, 8, "compression methods length"
    #  
    #  initial_value.session_id_length = 0 # session id not supported
    #  initial_value.cookie_length = 0 # cookie not implemented yet
    #  initial_value.compression_methods_length = 0 # compression not supported
    #end

    class DtlsHelloVerifyRequestHdr < BitStruct
      unsigned     :server_version,    16, "server version"
      unsigned     :cookie_length,      8, "cookie length"
      rest         :cookie,                "cookie"
    end

    #class CoapHdr < BitStruct
    #  unsigned    :coap_ver,          2,  "Version"
    #  unsigned    :coap_t,            2,  "Type"
    #  unsigned    :coap_tkl,          4,  "Token Length"
    #  unsigned    :coap_code_class,   3,  "Code/class"
    #  unsigned    :coap_code_detail,  5,  "Code/detail"
    #  unsigned    :coap_msgid,       16,  "Message ID"
    #  rest        :body,                  "Body of message"
    #
    #  note "Body contains optional token, options, 0xF delimitor and payload"
    #
    #  initial_value.coap_ver = 1
    #  initial_value.coap_tkl = 0
    #end

  end # Frame
end # Et

