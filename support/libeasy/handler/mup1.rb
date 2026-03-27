#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require_relative 'base.rb'

module Et
  module Handler
    class Mup1 < Base
      MUP1_SOF = 0x3e
      MUP1_EOF = 0x3c
      MUP1_ESC = 0x5c
      MUP1_NL  = 0x0d
      MUP1_00  = 0x30
      MUP1_FF  = 0x46

      MUP1_CB_ANNOUNCE = 0x41
      MUP1_CB_COAP = 0x43
      MUP1_CB_DTLS = 0x44
      MUP1_CB_PING = 0x50
      MUP1_CB_TRACE = 0x54
      MUP1_CB_NON_MUP1 = 0

      # CRC32 lookup table (polynomial 0xEDB88320)
      CRC32_TABLE = [
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
      ].freeze

      # Base128 encoding table
      BASE128_ENCODE = [
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
        0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
        0x7A, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
        0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
        0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
        0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
        0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
        0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
        0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD
      ].freeze

      # Base128 decoding table (reverse mapping)
      BASE128_DECODE = BASE128_ENCODE.each_with_index.to_h.freeze

      def initialize dut, tracer = nil, mup1_on = true, checksum_type = :internet
        super("MUP1", dut, tracer)
        @state = :init
        @raw_buf = ""
        @timeout_default = 0.5
        @checksum_type = checksum_type
        @announce_received = false  # Only enforce checksums after announce
        ll_handler_reg 0, self
        if mup1_on
          on()
        else
          off()
        end
      end

      def on
        t(:info, "MUP1 ON")
        @on = true
      end

      # When MUP1 is off, it will treat all output as normal console output
      def off
        t(:info, "MUP1 OFF")
        @on = false
      end

      def timeout_work
        return nil if not @on

        #t(:debug, "Timeout work")
        if @state != :init
          t(:info, "Reset SM (#{@state.to_s}) due to timeout")
          @state = :init
        end

        #t(:info, "timeout:")
        dispatch_raw()
      end

      def rx type, s
        @raw_buf += s.b if @raw_buf.size < 10240

        if not @on
          #t(:info, "not-on:")
          dispatch_raw
          return
        end

        #t(:debug, "RX state=#{@state.to_s}")
        timeout = nil

        s.unpack("C*").each do |c|
          timeout = rx_sm(c)
        end

        timeout_relative_set(timeout)
      end

      def rx_sm_sof 
        @state = :sof 
        @mup1_data = [] 
        @mup1_data_chk = [MUP1_SOF] 
        @mup1_chk = [] 
        @mup1_type = 0 
      end 

      def rx_sm c
        case @state
        when :init
          if c == MUP1_SOF
            rx_sm_sof()
          end

        when :sof
          @mup1_type = c
          @state = :data
          @mup1_data_chk << c

        when :data
          if @mup1_data.size > 1024
            t(:err, "Frame too big!")
            @state = :init
          else
            case c
            when MUP1_ESC
              @state = :esc

            when MUP1_EOF
              @mup1_data_chk += @mup1_data
              @mup1_data_chk << MUP1_EOF

              # Determine checksum size based on type
              @mup1_chk_expected = (@checksum_type == :crc32) ? 5 : 4

              # CRC32 never uses padding (single EOF always)
              # Internet checksum uses padding for even-sized payloads (two EOFs)
              if @checksum_type == :crc32
                # CRC32: always single EOF, no padding needed
                @state = :chk0
              elsif @mup1_data.size % 2 != 0
                # Internet checksum with odd payload: single EOF
                @state = :chk0
              else
                # Internet checksum with even payload: two EOFs for 16-bit alignment
                @state = :eof2
                @mup1_data_chk << MUP1_EOF
              end

            when MUP1_SOF
              t(:info, "Unexpected start of frame, aborting current frame")
              rx_sm_sof()

            when 0, 0xff
              t(:err, "invalid data element: '#{c}'")
              @state = :init

            else
              @mup1_data << c
            end
          end

        when :esc
          @state = :data
          case c
          when MUP1_SOF, MUP1_ESC, MUP1_EOF
            @mup1_data << c
          when MUP1_00
            @mup1_data << 0x00
          when MUP1_FF
            @mup1_data << 0xFF
          else
            t(:err, "invalid escape sequence: '#{c}'")
            @state = :init
          end

        when :eof2
          if c == MUP1_EOF
            @state = :chk0
          else
            t(:err, "Expected repeated esc, got #{c} / #{"%c" % c}")
            @state = :init
          end

        when :chk0
          @mup1_chk << c
          @state = (@mup1_chk.size < @mup1_chk_expected) ? :chk0 : :init

          # Check if we have all checksum bytes
          if @mup1_chk.size == @mup1_chk_expected
            # Calculate expected checksum
            if @checksum_type == :crc32
              crc = crc32_calc(@mup1_data_chk)
              chk_expected = to_base128(crc).unpack("C*")
            else
              chk_expected = checksum_calc_internet(@mup1_data_chk).unpack("C*")
            end

            if chk_expected != @mup1_chk
              # Only log checksum errors after announce is received
              # (early boot messages may use different checksum)
              if @announce_received
                t(:err, "Checksum error!")
                t(:err, "  Expected: #{chk_expected.map{|b| "%02x" % b}.join}")
                t(:err, "  Received: #{@mup1_chk.map{|b| "%02x" % b}.join}")
              end
            else
              #t(:info, "RX-MUP1: #{@raw_buf.inspect}")
              @raw_buf = ""
              #t(:info, "mup1 frame ready:       #{@mup1_data.pack("C*").inspect}")
              #t(:info, "mup1 frame ready-raw: #{@mup1_data_chk.pack("C*").inspect}")
              d = @mup1_data.pack("C*")

              # Mark announce as received when we get type 'A' with valid checksum
              if @mup1_type == 'A' && !@announce_received
                @announce_received = true
                t(:info, "Announce received - checksum validation now active")
              end

              handler_call_rx(@mup1_type, d)
            end
          end
        end

        return @timeout_default
      end

      def dispatch_raw
        buf = @raw_buf
        @raw_buf = ""
        if buf.size > 0
          #t(:info, "dispatch_raw: #{buf.inspect}")
          handler_call_rx(MUP1_CB_NON_MUP1, buf)
        end
      end

      def tx type, data = ""
        # Check if data payload exceeds MUP1 300 byte limit (LM_MUP1_DATA_SIZE)
        if data.size > 300
          raise "ERROR: MUP1 data size (#{data.size} bytes) exceeds 300 byte limit (LM_MUP1_DATA_SIZE)"
        end

        # Build the frame un-escaped to calculate checksum
        frame_a = [MUP1_SOF, type.ord] + data.unpack("C*") + [MUP1_EOF]
        # CRC32 never uses padding; Internet checksum pads even-sized payloads
        frame_a << MUP1_EOF if @checksum_type != :crc32 && data.size % 2 == 0

        # Calculate checksum based on type
        if @checksum_type == :crc32
          crc = crc32_calc(frame_a)
          cs = to_base128(crc)
        else
          cs = checksum_calc_internet(frame_a)
        end

        # Build the frame escaped to be injected
        frame = ">"
        frame << type
        if !data.nil?
          data_array = data.unpack("C*")
          escaped_data_array = Array.new
          data_array.each { |byte|
            if ((byte == MUP1_SOF) || (byte == MUP1_EOF) || (byte == MUP1_ESC) ||
                (byte == 0x00) || (byte == 0xFF))
              escaped_data_array << MUP1_ESC #Insert escape character '\'
            end
            if (byte == 0x00)
              byte = MUP1_00
            end
            if (byte == 0xFF)
              byte = MUP1_FF
            end
            escaped_data_array << byte
          }
          frame << escaped_data_array.pack("c*")
        end
        frame << "<"
        # CRC32 never uses padding (single EOF always)
        # Internet checksum uses padding for even-sized payloads (two EOFs)
        if @checksum_type != :crc32 && (data.nil? || ((data.size % 2) == 0))
          frame << "<"
        end
        frame << cs

        t(:info, "TX-MUP1: #{frame.inspect}")
        ll_tx frame
      end

      def crc32_calc(data)
        crc = 0xFFFFFFFF
        data.each do |byte|
          index = (crc ^ byte) & 0xFF
          crc = (crc >> 8) ^ CRC32_TABLE[index]
        end
        crc ^ 0xFFFFFFFF
      end

      def to_base128(value)
        # Extract 5 base-128 digits (7 bits each) in big-endian order
        digits = []
        5.times do |i|
          shift = (4 - i) * 7
          digit = (value >> shift) & 0x7F
          digits << BASE128_ENCODE[digit]
        end
        digits.pack("C*")
      end

      def from_base128(encoded)
        return nil if encoded.size != 5
        value = 0
        encoded.unpack("C*").each_with_index do |byte, i|
          digit = BASE128_DECODE[byte]
          return nil if digit.nil?
          value |= digit
          value <<= 7 if i < 4
        end
        value
      end

      def checksum_calc_internet data
        sum = data.pack("C*").unpack("n*").sum

        # Add carry twice (the first addition may cause another, e.g. 0x1ffff)
        sum = ((sum >> 16) + (sum & 0xffff))
        sum = ((sum >> 16) + (sum & 0xffff))

        sum = ~sum
        sum = sum & 0xFFFF

        #Convert checksum to ascii string
        ascii = "%.4x" %sum

        return ascii
      end

      def poll
        ll_poll()
      end
    end # Mup1 < Base
  end # Handler
end # Et
