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

      def initialize dut, tracer = nil, mup1_on = true
        super("MUP1", dut, tracer)
        @state = :init
        @raw_buf = ""
        @timeout_default = 0.5
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

              if @mup1_data.size % 2 != 0
                # We have an odd sized header, meaning that even sized message shall
                # lead to single EOF
                @state = :chk0
              else
                # We have an odd sized header, meaning that odd sized message shall
                # lead to two EOF
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
          @state = :chk1

        when :chk1
          @mup1_chk << c
          @state = :chk2

        when :chk2
          @mup1_chk << c
          @state = :chk3

        when :chk3
          @mup1_chk << c
          @state = :init

          chk = checksum_calc(@mup1_data_chk).unpack("C*")
          if chk != @mup1_chk
            t(:err, "Checksum error!")
          else
            #t(:info, "RX-MUP1: #{@raw_buf.inspect}")
            @raw_buf = ""
            #t(:info, "mup1 frame ready:       #{@mup1_data.pack("C*").inspect}")
            #t(:info, "mup1 frame ready-raw: #{@mup1_data_chk.pack("C*").inspect}")
            d = @mup1_data.pack("C*")
            handler_call_rx(@mup1_type, d)
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
        # Build the frame un-escaped to calculate checksum
        frame_a = [MUP1_SOF, type.ord] + data.unpack("C*") + [MUP1_EOF]
        frame_a << MUP1_EOF if data.size % 2 == 0
        cs = checksum_calc frame_a

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
        if (data.nil? || ((data.size % 2) == 0))
          frame << "<"
        end
        frame << cs

        t(:info, "TX-MUP1: #{frame.inspect}")
        ll_tx frame
      end

      def checksum_calc data
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
