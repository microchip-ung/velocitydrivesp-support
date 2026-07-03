#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require "uri"
require_relative 'base.rb'

module Et
  module Handler
    class Dut < Base
      def initialize uri, baud: 115200
        u = URI(uri)

        case u.scheme
        when "termhub", "telnet"
          super "TCP"
          @socket = TCPSocket.open(u.host, u.port)

          if u.scheme == "telnet"
            # Enter binary mode, and flush what ever the term server have in the
            # pipeline
            @socket.write [0xff, 0xfb, 0x03, 0xff, 0xfd, 0x03, 0xff, 0xfd, 0x01].pack("C*")
            IO.select([@stream], nil, nil, 1)
            @socket.recv_nonblock 1024
          end
        when nil
          require "serialport"
          super "UART"
          conf = {
            "baud"      => baud,
            "data_bits" => 8,
            "stop_bits" => 1,
            "parity"    => SerialPort::NONE
          }
          @socket = SerialPort.new(uri, conf)
          @socket.flow_control = SerialPort::NONE
        else
          raise "Unsupported scheme: #{u.scheme}"
        end
      end

      def sleep sec
        ts = Time.now + sec

        t_i "Sleeping #{sec} seconds"
        while Time.now < ts
          timeout_abs_set ts
          poll()
        end
      end

      def poll
        #puts "DUT-Poll"
        timeout = nil

        loop_cnt = 0

        now = Time.now
        timeout_calc_next()
        if @timeout_next
          if now < @timeout_next
            timeout = @timeout_next - now
          else
            timeout = 0
          end
        else
          raise "Calling poll without a timeout is an error" if loop_cnt == 0
          return
        end

        #puts "POLL: Pre select, abs: #{@timeout_next} timeout: #{timeout}"
        res = IO.select([@socket], [], [], timeout)
        loop_cnt += 1

        if res.nil?
          #puts " -> Select timeout"
          timeout_cb()
        else
          if res[0][0]
            x = res[0][0].read_nonblock(128)
            #puts " -> Select read ready, got #{x.size} bytes"
            handler_broadcast_rx(x)
          else
            #puts " -> Select unexpected..."
          end
        end
      end

      def timeout_work
      end

      def tx data
        @socket.write data
      end
    end # Dut < Base
  end # Handler
end # Et
