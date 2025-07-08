#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'uri'
require_relative 'base.rb'
require_relative '../frame/coap.rb'

module Et
  module Handler
    class Coap < Base
      class ReqBlockWise
        attr_reader :mid, :payload_rx, :code_class, :code_detail

        RETRANSMIT_TIME_SEC = 3
        def initialize base, code, uri, payload = nil, opts = {}
          @base = base
          @mid = nil
          @method = code
          @uri = uri
          @payload_tx = payload
          @payload_rx = ""
          @opts = opts
          @state = :state_req_tx

          # Keeps track on how much of the request has been send and ack'ed
          @req_tx = nil
          @req_tx_ack = nil

          @res_more = false
          @res_bs = nil
          @res_num = nil

          # Keeps track on how much of the response has been received
        end

        def req_not_done
          if @req_tx.nil? or (@req_tx != @req_tx_ack)
            #puts "req_not_done: #{@req_tx.nil?} or (#{@req_tx} != #{@req_tx_ack}) -> true"
            return true
          end

          if @payload_tx and @req_tx != @payload_tx.bytesize
            #puts "req_not_done: #{@req_tx} != #{@payload_tx.bytesize} -> true"
            return true
          end

          #puts "req_not_done: false"
          return false
        end

        def rx_data frame
          if @mid.nil? or frame.msgid != @mid
            #puts "mmsgid does not match! #{frame.msgid} != #{@mid}"
            return next_step()
          end

          if frame.type == Frame::Coap::TYPE_ACK and frame.code_class == 2
            # TODO, guess more checks are needed
            @req_tx_ack = @req_tx
          end

          @mid = nil
          @req_timer = nil
          @code_class = frame.code_class
          @code_detail = frame.code_detail
          @payload_rx += frame.payload if frame.payload

          #puts frame.block2_more
          if frame.block2_more and frame.block2_more == 1
            @res_more = true
            @res_bs = frame.block2_block_size
            @res_num = frame.block2_num
          else
            @res_more = false
          end

          if frame.code_class == 5 or frame.code_class == 4
            return nil, nil
          else
            return next_step
          end
        end

        # Next step: Returns the next step in the request/response state-machine
        # in form of a (timer, frame) tuple.
        # The following variants are allowed:
        # (nil, nil): No next step - we are done - you can use the result
        # (time-val, frame): Frame needs to be TX'ed, and timer needs to be set
        # (time-val, nil): Frame already send, continue waiting.
        def next_step
          #puts "next-step"
          ts = Time.now

          if @req_timer
            if ts >= @req_timer
              if @retry < 5
                @base.t(:info, "Retransmit #{@retry}")
                # TODO, implement exponential push back
                @req_timer = ts + RETRANSMIT_TIME_SEC
                @retry += 1
                return @req_timer, @last_frame
              else
                #puts "next-step -> STOP retrying"
                @base.t(:err, "Giving up!")
                @req_timer = nil
                return nil, nil
              end
            else
              # Continue waiting...
              #puts "next-step -> Timer already started"
              return @req_timer, nil
            end
          end

          f = Frame::Coap.new
          f.accept = @opts[:accept] if @opts[:accept]
          f.type = Frame::Coap::TYPE_CONFIRMABLE
          f.code_class = 0 # request mesage
          f.code_detail = @method

          @mid = rand(2**16)
          #puts "msgid generated: #{@mid}"
          f.msgid = @mid

          u = URI(@uri)
          if u and u.path
            f.uri_paths = u.path.split("/").select{|x| x.bytesize > 0}
          end

          if u and u.query
            f.uri_keys = URI::decode_www_form(u.query).collect do |x|
              if x[1].bytesize > 0
                x.collect{|y| URI.encode_www_form_component(y) }.join("=")
              else
                URI.encode_www_form_component(x[0])
              end
            end
          end

          # Always put a block2 option to ask the server to fragment the response.
          # Even put/post can genrate error messages which may need to be fragmented
          f.block2_block_size = 256 # configurable?
          f.block2_more = 0
          f.block2_num = 0

          @retry = 0
          if req_not_done()
            @req_tx = 0 if @req_tx.nil?

            if @payload_tx
              f.content_type = @opts[:content_type] if @opts[:content_type]
              if @payload_tx.bytesize > 256
                start = 0
                start = @req_tx_ack if @req_tx_ack
                f.payload = @payload_tx.byteslice(start, 256)

                f.block1_block_size = 256 # configurable?
                f.block1_num = @req_tx / 256

                @req_tx += f.payload.bytesize
                if @req_tx < @payload_tx.bytesize
                  f.block1_more = 1
                else
                  f.block1_more = 0
                end

              else
                f.payload = @payload_tx
                @req_tx = @payload_tx.bytesize
              end
            end

            @last_frame = f
            @req_timer = ts + RETRANSMIT_TIME_SEC
            #puts "next-step -> requesting"
            return @req_timer, @last_frame

          elsif @res_more
            f.block2_num = @res_num + 1
            @last_frame = f
            @req_timer = ts + RETRANSMIT_TIME_SEC
            #puts "next-step -> read-out-response"
            return @req_timer, @last_frame
          else
            #puts "next-step -> DONE"
            @last_frame = nil
            @req_timer = nil
            return nil, nil
          end
        end
      end # ReqBlockWise

      def initialize lower_layer, tracer = nil
        super "CoAP", lower_layer, tracer
        if lower_layer.instance_of? Mup1
          ll_handler_reg Mup1::MUP1_CB_COAP, self
        elsif lower_layer.instance_of? Dtls_Application
          ll_handler_reg 0, self
        else
          t(:err, "Coap.initialize: lower_layer is unknown");
        end
      end

      def rx type, data
        f = Frame::Coap.new data
        t(:info, "RX: #{f.to_s}")
        if @req
          ts, f = @req.rx_data f
          timeout_abs_set(ts)
          tx(f)
        end
      end

      def req_done
        @timeout_self.nil?
      end

      def coap_req code, uri, payload = nil, opts = {}
        @req = ReqBlockWise.new self, code, uri, payload, opts
        ts, f = @req.next_step
        timeout_abs_set(ts)
        tx(f)
      end

      def req method, uri, data = nil, opts = {}
        coap_req method, uri, data, opts
        while @timeout_self
          ll_poll()
        end

        res = @req
        @req = nil
        return res
      end

      def get uri, opts = {}
        return req(Frame::Coap::CODE_GET, uri, nil, opts)
      end

      def put uri, data, opts = {}
        return req(Frame::Coap::CODE_PUT, uri, data, opts)
      end

      def del uri, opts = {}
        return req(Frame::Coap::CODE_DEL, uri, nil, opts)
      end

      def post uri, data, opts = {}
        return req(Frame::Coap::CODE_POST, uri, data, opts)
      end

      def fetch uri, data, opts = {}
        return req(Frame::Coap::CODE_FETCH, uri, data, opts)
      end

      def ipatch uri, data, opts = {}
        return req(Frame::Coap::CODE_IPATCH, uri, data, opts)
      end

      def tx frame
        if frame
          t(:info, "TX: #{frame.to_s}")
          if @lower_layer.instance_of? Mup1
            # TODO, fix magic number
            ll_tx 0x63, frame.enc
          elsif @lower_layer.instance_of? Dtls_Application
            ll_tx frame.enc
          else
            t(:err, "Coap.initialize: lower_layer is unknown");
          end
        end
      end

      def timeout_work
        if @req.nil?
          return
        end

        ts, f = @req.next_step
        timeout_abs_set(ts)
        tx(f)
      end

    end # Coap < Base
  end # Handler
end # Et
