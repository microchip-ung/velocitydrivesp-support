#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'bit-struct'

module Et
  module Frame
    class CoapOptHdr < BitStruct
      unsigned    :coap_opt_delta,   4,     "Option Delta Value"
      unsigned    :coap_opt_length,  4,     "Option Length"
      rest        :body,                    "Body of message"
    end

    class CoapHdr < BitStruct
      unsigned    :coap_ver,          2,  "Version"
      unsigned    :coap_t,            2,  "Type"
      unsigned    :coap_tkl,          4,  "Token Length"
      unsigned    :coap_code_class,   3,  "Code/class"
      unsigned    :coap_code_detail,  5,  "Code/detail"
      unsigned    :coap_msgid,       16,  "Message ID"
      rest        :body,                  "Body of message"

      note "Body contains optional token, options, 0xF delimitor and payload"

      initial_value.coap_ver = 1
      initial_value.coap_tkl = 0
    end

    class Coap
      COAP_CLASS_REQ = 0
      COAP_CLASS_RES_SUCCESS = 2
      COAP_CLASS_RES_CLIENT_ERROR = 4
      COAP_CLASS_RES_SERVER_ERROR = 5

      CODE_PING = 0
      CODE_GET = 1
      CODE_POST = 2
      CODE_PUT = 3
      CODE_DEL = 4
      CODE_FETCH = 5
      CODE_IPATCH = 7

      TYPE_CONFIRMABLE = 0
      TYPE_NON_CONFIRMABLE = 1
      TYPE_ACK = 2
      TYPE_RESET = 3

      CT_UNSPECIFIED                =  -1
      CT_TEXT_PLAIN                 =   0
      CT_APPL_LINK                  =  40
      CT_APPL_XML                   =  41
      CT_APPL_JSON                  =  50
      CT_APPL_CBOR                  =  60
      CT_APPL_YANG_DATA_CBOR        = 140
      CT_APPL_YANG_IDENTIFIERS_CBOR = 141
      CT_APPL_YANG_INSTANCES_CBOR   = 142

      OPT_IF_MATCH       =  1 # opaque (not implemented)
      OPT_URI_HOST       =  3 # string (not implemented)
      OPT_ETAG           =  4 # opaque (not implemented)
      OPT_IF_NONE_MATCH  =  5 # empty (not implemented)
      OPT_URI_PORT       =  7 # uint (not implemented)
      OPT_LOCATION_PATH  =  8 # string (not implemented)
      OPT_URI_PATH       = 11 # string
      OPT_CONTENT_FORMAT = 12 # uint
      OPT_MAX_AGE        = 14 # uint (not implemented)
      OPT_URI_QUERY      = 15 # string
      OPT_ACCEPT         = 17 # uint
      OPT_LOCATION_QUERY = 20 # string (not implemented)
      OPT_BLOCK2         = 23 # Block2
      OPT_BLOCK1         = 27 # Block1

      OPT_PROXY_URI      = 35 # string (not implemented)
      OPT_PROXY_SCHEME   = 39 # string (not implemented)
      OPT_SIZE1          = 60 # uint (not implemented)

      COAP_ACK_WAIT_TIME = 1       # Wait for ACK in one second then retransmit
      COAP_LAST_ACK_WAIT_TIME = 5  # Wait for the last ACK

      attr_accessor :type, :code_class, :code_detail, :payload, :msgid, :token
      attr_accessor :uri_paths
      attr_accessor :uri_keys
      attr_accessor :content_type
      attr_accessor :accept

      attr_accessor :block1_block_size
      attr_accessor :block1_more
      attr_accessor :block1_num

      attr_accessor :block2_block_size
      attr_accessor :block2_more
      attr_accessor :block2_num

      def initialize data = nil
        return if data.nil?

        h = CoapHdr.new data
        if h.coap_ver != 1
          @parse_error = "Unexpected version: #{h.coap_ver}"
          return
        end

        @type = h.coap_t
        @code_class = h.coap_code_class
        @code_detail = h.coap_code_detail
        @msgid = h.coap_msgid
        @uri_paths = []
        @uri_keys = []
        data = h.body.unpack("C*")

        if h.coap_tkl > 0
          if data.size < h.coap_tkl
            @parse_error = "Token not present in data"
            return
          end
          @token = data.shift(h.coap_tkl).pack("C*")
        end

        return if data.size == 0

        # pop options while present
        opt_number = 0
        while data.size > 0 && data[0] != 255
          opthdr = CoapOptHdr.new(data.shift(1).pack("C"))
          option_size = 0
          opt_delta = 0
          if opthdr.coap_opt_delta == 13
            if data.size < 1
              @parse_error = "underflow in option"
              return
            end
            opt_delta = data.shift(1)[0] + 13

          elsif opthdr.coap_opt_delta == 14
            if data.size < 2
              @parse_error = "underflow in option"
              return
            end
            opt_delta = data.shift(2).pack("C*").unpack("n") + 269

          elsif opthdr.coap_opt_delta == 15
            @parse_error = "Reserved option delta!"
            return
          else
            opt_delta = opthdr.coap_opt_delta
          end

          val_size = 0
          if opthdr.coap_opt_length == 13
            if data.size < 1
              @parse_error = "underflow in option"
              return
            end
            val_size = data.shift(1)[0] + 13

          elsif opthdr.coap_opt_length == 14
            if data.size < 2
              @parse_error = "underflow in option"
              return
            end
            val_size = data.shift(2).pack("C*").unpack("n") + 269

          elsif opthdr.coap_opt_length == 15
            @parse_error = "Reserved option delta!"
            return
          else
            val_size = opthdr.coap_opt_length
          end

          if data.size < val_size
            @parse_error = "underflow option value"
            return
          end

          opt_number += opt_delta

          case opt_number
          when OPT_URI_PATH
            @uri_paths << data.shift(val_size).pack("c*")
          when OPT_CONTENT_FORMAT
            @content_type = opt_uint_dec(data.shift(val_size))
          when OPT_URI_QUERY
            @uri_keys << data.shift(val_size).pack("c*")
          when OPT_ACCEPT
            @accept = opt_uint_dec(data.shift(val_size))
          when OPT_BLOCK1
            @block1_num, @block1_more, @block1_block_size = opt_block_dec(data.shift(val_size))
          when OPT_BLOCK2
            @block2_num, @block2_more, @block2_block_size = opt_block_dec(data.shift(val_size))
          else
            #STDERR.puts "Skipping option #{opt_number}"
            data.shift(val_size)
          end
        end

        return if data.size == 0

        delim = data.shift(1).first
        if delim != 255
          @parse_error = "Unexpected delimitor #{delim}"
          return
        end
        @payload = data.pack("c*")
      end

      def opt_delta val_last, val_cur
        if val_cur < val_last
          @parse_error = "Wrong option order"
          return
        end
        v = val_cur - val_last
        return val_cur, v
      end

      def to_s
        if @parse_error
          return "ERROR: #{@parse_error}"
        end

        s = ""
        case @type
        when TYPE_CONFIRMABLE
          s += "CON"
        when TYPE_NON_CONFIRMABLE
          s += "NON"
        when TYPE_ACK
          s += "ACK"
        when TYPE_RESET
          s += "RST"
        else
          raise "should not happend: #{@type}"
        end
        s += " [MID=0x%04x]" % [@msgid]

        case @code_class
        when COAP_CLASS_REQ

          uri_ = ""
          if @uri_paths and @uri_paths.size > 0
            uri_ += @uri_paths.collect{|p| "/#{p}"}.join("")
          end
          if @uri_keys and @uri_keys.size > 0
            uri_ += "?"
            uri_ += @uri_keys.join("&")
          end

          uri = ""
          uri = " #{uri_}" if uri_.size > 0

          case @code_detail
          when CODE_PING
            s += " PING#{uri}"
          when CODE_GET
            s += " GET#{uri}"
          when CODE_POST
            s += " POST#{uri}"
          when CODE_PUT
            s += " PUT#{uri}"
          when CODE_DEL
            s += " DEL#{uri}"
          when CODE_FETCH
            s += " FETCH#{uri}"
          when CODE_IPATCH
            s += " IPATCH#{uri}"
          else
            s += " %d.%02d" % [@code_class, @code_detail]
          end
        else
          s += " %d.%02d" % [@code_class, @code_detail]
        end

        if @token
          s += " Token=0x" + @token.unpack("H*")[0]
        end

        s += " ac=#{@accept}" if @accept
        s += " ct=#{@content_type}" if @content_type

        if @block1_num
          s += " 1:#{@block1_num}/#{@block1_more}/#{@block1_block_size}"
        end

        if @block2_num
          s += " 2:#{@block2_num}/#{@block2_more}/#{@block2_block_size}"
        end

        if @payload and @payload.size > 0
          s += " PAYLOAD="
          s += @payload.unpack("H*")[0]
        end

        return s
      end

      def opt_val_enc v
        if v < 13
          return v, ""
        elsif v <= 268
          v -= 13
          return 13, [v].pack("C")
        elsif v < 65536
          v -= 269
          return 14, [v].pack("n")
        else
          raise "Invalid value"
        end
      end

      def opt_enc delta, payload
        h = CoapOptHdr.new
        d, d_ext = opt_val_enc(delta)
        pl, pl_ext = opt_val_enc(payload.size)

        h.coap_opt_delta = d
        h.coap_opt_length = pl
        h << d_ext
        h << pl_ext
        h << payload
        h
      end

      def opt_block_dec arr
        val = opt_uint_dec(arr)
        szx = val & 0x7
        val >>= 3
        m = val & 1
        val >>= 1
        return val, m, 2**(szx + 4)
      end

      def opt_uint_dec v
        case v.size
        when 0
          v.unshift(0, 0, 0, 0)
        when 1
          v.unshift(0, 0, 0)
        when 2
          v.unshift(0, 0)
        when 3
          v.unshift(0)
        when 4
          # do nothing
        else
          raise "unexpected size"
        end

        return v.pack("C*").unpack("N").first
      end

      def opt_uint_enc v
        if v == 0
          return ""
        elsif v < 256
          [v].pack("C")
        elsif v < 65536
          [v].pack("n")
        elsif v < 16777216
          [v].pack("N")[1..3]
        else
          [v].pack("N")
        end
      end


      def opt_block_enc num, m, block_size
        szx = 0
        case block_size
        when 16
          szx = 0
        when 32
          szx = 1
        when 64
          szx = 2
        when 128
          szx = 3
        when 256
          szx = 4
        when 512
          szx = 5
        when 1024
          szx = 6
        else
          raise "invalid block size"
        end

        val = szx
        if m != 0
          val += 8
        end

        val += (num << 4)

        return opt_uint_enc val
      end

      def enc
        h = CoapHdr.new
        h.coap_t = @type
        h.coap_code_class = @code_class
        h.coap_code_detail = @code_detail
        h.coap_msgid = @msgid
        h.coap_tkl = @token.size if @token

        opt_last = 0
        if @uri_paths
          @uri_paths.each { |opt|
            if opt.length > 0
              opt_last, opt_delta = opt_delta(opt_last, OPT_URI_PATH)
              h << opt_enc(opt_delta, opt)
            end
          }
        end

        if @content_type
          opt_last, opt_delta = opt_delta(opt_last, OPT_CONTENT_FORMAT)
          h << opt_enc(opt_delta, opt_uint_enc(@content_type))
        end

        if @uri_keys
          @uri_keys.each { |opt|
            if opt.length > 0
              opt_last, opt_delta = opt_delta(opt_last, OPT_URI_QUERY)
              h << opt_enc(opt_delta, opt)
            end
          }
        end

        if @accept
          opt_last, opt_delta = opt_delta(opt_last, OPT_ACCEPT)
          h << opt_enc(opt_delta, opt_uint_enc(@accept))
        end

        if @block2_block_size and @block2_more and @block2_num
          opt_last, opt_delta = opt_delta(opt_last, OPT_BLOCK2)
          h << opt_enc(opt_delta, opt_block_enc(@block2_num, @block2_more, @block2_block_size))
        end

        if @block1_block_size and @block1_more and @block1_num
          opt_last, opt_delta = opt_delta(opt_last, OPT_BLOCK1)
          h << opt_enc(opt_delta, opt_block_enc(@block1_num, @block1_more, @block1_block_size))
        end

        if @payload && (@payload !="")
          h << [255].pack("C")
          h << @payload
        end

        return h
      end
    end # Coap
  end # Frame
end # Et

