#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'cbor-pure'
require 'treetop'
require 'cbor-diag-parser'
require 'cbor-pretty'
require 'cbor-diagnostic'
require 'cbor-packed'
require 'cbor-deterministic'
require 'cbor-canonical'
require 'cbor-diagnostic-helper'

def diag2cbor(diag)
    parser = CBOR_DIAGParser.new
    i = diag
    if result = parser.parse(i)
        decoded = result.to_rb
        out = case decoded
              when CBOR::Sequence
                  CBOR::encode_seq(decoded.elements)
              else
                  CBOR::encode(decoded)
              end
        return out
    else
        raise "/*** Can't parse #{i}\n#{parser.failure_reason}"
    end
end

def cbor2diag(cbor)
    diag = ''
    options = cbor_diagnostic_process_args("cdetpqu")
    i = cbor
    totalsize = i.bytesize
    while !i.empty?
        begin
            o, i = CBOR.decode_with_rest(i)
        rescue Exception => e
            raise "/*** Garbage at byte #{totalsize-i.bytesize}: #{e.message} /"
        end
        diag += cbor_diagnostic_output(o, options)
        diag += ', ' if !i.empty?
    end
    diag
end

