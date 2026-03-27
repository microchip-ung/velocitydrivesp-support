#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

module Et
  module Handler
    class Base
      attr_reader :timeout_self, :timeout_next
      @@basetime = Time.now

      def initialize name, lower_layer = nil, tracer = nil
        @name = name
        @lower_layer = lower_layer
        @handlers = {}
        @timeout_self = nil # need to call self.timeout_work
        @timeout_next = nil # this module, or one of the handlers min
        @tracer = tracer
      end

      def ts t
        if t.nil?
          "nil"
        else
          "%5.1f" % [t - @@basetime]
        end
      end

      def ts_next
        ts @timeout_work
      end

      def ts_self
        ts @timeout_self
      end

      def ll_handler_reg type, handler
        @lower_layer.handler_reg type, handler
      end

      def ll_tx *args
        @lower_layer.timeout_calc_next()
        @lower_layer.tx *args
      end

      def ll_poll
        @lower_layer.timeout_calc_next()
        @lower_layer.poll
      end

      def handler_reg type, handler
        obj = @handlers[type]
        if obj
          obj << handler
        else
          @handlers[type] = [handler]
        end
      end

      def handler_clear type
        @handlers[type] = []
      end

      def t(level, msg)
        raise "Invalid level" if not [:fatal, :err, :info, :debug].include? level

        if @tracer
          @tracer.t(@name, level, msg)
        else
          puts "#{@name} #{msg}"
        end
      end

      def handler_broadcast_rx data
        @handlers.each do |k, v|
          v.each do |h|
            h.rx(k, data)
          end
        end

        timeout_calc_next()
      end

      def handler_call_rx type, data
        h = @handlers[type]
        if h.nil?
          t(:info, "No handler for #{type}")

          # Add an empty list of handlers to avoid repeating this message
          @handlers[type] = []
        else
          h.each do |hh|
            hh.rx type, data
          end
        end

        timeout_calc_next()
      end

      def timeout_cb
        t = Time.now
        if @timeout_self and t >= @timeout_self
          @timeout_self = nil
          self.timeout_work()
        end

        @handlers.each do |k, v|
          v.each do |h|
            h.timeout_cb()
          end
        end

        timeout_calc_next()
      end

      def timeout_calc_next
        min = @timeout_self

        @handlers.each do |k, v|
          v.each do |h|
            if min.nil?
              min = h.timeout_next # does not matted if h.timeout_next.nil?
            elsif h.timeout_next.nil?
              # do nothing
            elsif h.timeout_next < min
              min = h.timeout_next
            end
          end
        end

        @timeout_next = min
        @lower_layer.timeout_calc_next() if @lower_layer
      end

      def timeout_relative_set to
        if to
          @timeout_self = Time.now + to
        else
          @timeout_self = nil
        end

        timeout_calc_next()
      end

      def timeout_abs_set to
        @timeout_self = to
        timeout_calc_next()
      end

      def timeout_clear
        @timeout_self = nil
        timeout_calc_next()
      end

    end # Base
  end # Handler
end # Et
