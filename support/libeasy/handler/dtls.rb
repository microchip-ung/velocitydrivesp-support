#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'uri'
require_relative 'base.rb'
require_relative '../frame/dtls.rb'
require 'openssl'
require 'fiddle'
require 'fiddle/struct'
require 'fiddle/cparser'
include Fiddle::CParser

module Et
  module Handler
    class Dtls_Config
      EXTENSION_FORCE_OFF = 0 # don't use this extension
      EXTENSION_PREFER_ON = 1 # offer extension, but allow server to reject it
      EXTENSION_FORCE_ON = 2 # offer extension, and don't allow server to reject it
      attr_accessor :extended_master_secret, :pem_key
      def initialize pem_key
        @pem_key = pem_key
        @extended_master_secret = EXTENSION_PREFER_ON
      end
    end
    class Dtls_Application < Base
      def initialize hs, lower_layer, tracer = nil
        super "DTLS_APP", lower_layer, tracer
        if !(hs.instance_of? Dtls_Handshake)
          raise "invalid handshake object"
        end
        if !(lower_layer.instance_of? Dtls_Record)
          raise "unexpected lower layer"
        end
        ll_handler_reg Dtls_Record::DTLS_CT_APPLICATION_DATA, self
        @content_type = nil
        @record = lower_layer
        @hs = hs
      end
      def tx data
        if !(@record.is_secure)
          @hs.do_handshake
        end
        if @record.is_secure
          ll_tx Dtls_Record::DTLS_CT_APPLICATION_DATA, data
        else
          t(:err, "Secure Channel could not be established, dropping frame")
        end
      end
      def rx type, data
        if (type != Dtls_Record::DTLS_CT_APPLICATION_DATA)
          raise "Dtls_Application.rx: unexpected content type"
        end
        if (@content_type == nil)
          raise "handler not registered"
        end
        handler_call_rx @content_type, data
      end
      def handler_reg type, handler
        if (@content_type != nil)
          raise "handler already registered"
        end
        @content_type = type
        super type, handler
      end
      def poll
        ll_poll()
      end
    end # Dtls_Application

    class Dtls_ChangeCipherSpec < Base
      def initialize lower_layer, tracer = nil
        super "DTLS_CCS", lower_layer, tracer
        if !(lower_layer.instance_of? Dtls_Record)
          raise "unexpected lower layer"
        end
        @record = lower_layer
        ll_handler_reg Dtls_Record::DTLS_CT_CHANGE_CIPHER_SPEC, self
      end
      def handshake_set hs
        @hs = hs
      end
      def send_client_change_cipher_spec
        if (@hs == nil)
          #  need access to handshake protocol, for state checking/setting
          raise "@hs == nil"
        end
        @hs.hs_check(@hs.hs_state == Dtls_Handshake::DTLS_HS_STATE_SEND_CLIENT_CHANGE_CIPHER_SPEC)
        msg = [1].pack("C")
        ll_tx Dtls_Record::DTLS_CT_CHANGE_CIPHER_SPEC, msg
        #puts "sent client change cipher spec"
        @record.pending_write_security_params_activate
        @hs.hs_state = Dtls_Handshake::DTLS_HS_STATE_SEND_CLIENT_FINISHED
      end
      def rx type, data
        if (type != Dtls_Record::DTLS_CT_CHANGE_CIPHER_SPEC)
          raise "Dtls_ChangeCipherSpec.rx: unexpected content type"
        end
        if (@hs == nil)
          #  need access to handshake protocol, for state checking/setting
          raise "@hs == nil"
        end
        @hs.hs_check(@hs.hs_state == Dtls_Handshake::DTLS_HS_STATE_WAIT_FOR_SERVER_CHANGE_CIPHER_SPEC)
        if (data.length != 1)
          raise "data.length != 1"
        end
        if (data.unpack("C")[0] != 1)
          raise "unexpected value for Change cipher spec"
        end
        #puts "processing server change cipher spec"
        @record.pending_read_security_params_activate
        @hs.hs_state = Dtls_Handshake::DTLS_HS_STATE_WAIT_FOR_SERVER_FINISHED
      end
    end # Dtls_ChangeCipherSpec

    class Dtls_Handshake < Base
      DTLS_HS_HELLO_REQUEST = 0
      DTLS_HS_CLIENT_HELLO = 1
      DTLS_HS_SERVER_HELLO = 2
      DTLS_HS_HELLO_VERIFY_REQUEST = 3
      DTLS_HS_CERTIFICATE = 11
      DTLS_HS_SERVER_KEY_EXCHANGE = 12
      DTLS_HS_CERTIFICATE_REQUEST = 13
      DTLS_HS_SERVER_HELLO_DONE = 14
      DTLS_HS_CERTIFICATE_VERIFY = 15
      DTLS_HS_CLIENT_KEY_EXCHANGE = 16
      DTLS_HS_FINISHED = 20

      # TLS cipher suite codes
      TLS_NULL_WITH_NULL_NULL = 0x0000
      TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8 # see RFC6655
      TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE # see RFC7251

      # TLS compression methods
      TLS_COMPRESSION_NULL = 0

      # The following extension types are defined at
      #   https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
      TLS_EXT_SUPPORTED_GROUPS        = 10 # See RFC8422, RFC7919
      TLS_EXT_EC_POINT_FORMATS        = 11 # See RFC8422
      TLS_EXT_SIGNATURE_ALGORITHMS    = 13 # See RFC8446
      TLS_EXT_CLIENT_CERTIFICATE_TYPE = 19 # See RFC7250
      TLS_EXT_SERVER_CERTIFICATE_TYPE = 20 # See RFC7250
      TLS_EXT_EXTENDED_MASTER_SECRET  = 23 # See RFC7627
      
      # The following certificate Types are defined at
      #   https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-3
      TLS_CERT_TYPE_X509           = 0 # See RFC6091, and RFC Errata 5976
      TLS_CERT_TYPE_OPEN_PGP       = 1 # See RFC6091, and RFC8446
      TLS_CERT_TYPE_RAW_PUBLIC_KEY = 2 # See RFC7250

      # The following supported groups are defined at
      #   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
      TLS_SUPPORTED_GROUP_SECP256R1 = 23

      DTLS_SECP256R1_KEY_SIZE = 32

      # The following ec point formats are defined at
      #   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9
      TLS_EC_POINT_FORMAT_UNCOMPRESSED = 0
      
      # The following signature algorithms are defined at
      #   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
      TLS_SIGNATURE_ALGORITHM_ECDSA = 3 # see RFC5246
      
      # The following hash algorithms are defined at
      #   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
      TLS_HASH_ALGORITHM_SHA256 = 4 # See RFC5246

      TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN = 64 # See RFC 4492
      
      ASN1_CERTIFICATE_HEADER = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
        0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
        0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04]

      DTLS_MASTER_SECRET_SIZE = 48

      DTLS_MAC_KEY_SIZE = 0
      DTLS_ENC_KEY_SIZE = 16
      DTLS_FIXED_IV_SIZE = 4
      DTLS_KEY_BLOCK_SIZE = 
        ((2 * DTLS_MAC_KEY_SIZE) +
         (2 * DTLS_ENC_KEY_SIZE) + 
         (2 * DTLS_FIXED_IV_SIZE))

      # handshake states
      DTLS_HS_STATE_IDLE = 0
      DTLS_HS_STATE_SEND_CLIENT_HELLO_NO_COOKIE = 1
      DTLS_HS_STATE_WAIT_FOR_HELLO_VERIFY_REQUEST = 2
      DTLS_HS_STATE_SEND_CLIENT_HELLO_WITH_COOKIE = 3
      DTLS_HS_STATE_WAIT_FOR_SERVER_HELLO = 4
      DTLS_HS_STATE_WAIT_FOR_SERVER_CERTIFICATE = 5
      DTLS_HS_STATE_WAIT_FOR_SERVER_KEY_EXCHANGE = 6
      DTLS_HS_STATE_WAIT_FOR_CERTIFICATE_REQUEST = 7
      DTLS_HS_STATE_WAIT_FOR_SERVER_HELLO_DONE = 8
      DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE = 9
      DTLS_HS_STATE_SEND_CLIENT_KEY_EXCHANGE = 10
      DTLS_HS_STATE_CALC_MASTER_SECRET = 11
      DTLS_HS_STATE_CALC_SECURITY_PARAMS = 12
      DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE_VERIFY = 13
      DTLS_HS_STATE_SEND_CLIENT_CHANGE_CIPHER_SPEC = 14
      DTLS_HS_STATE_SEND_CLIENT_FINISHED = 15
      DTLS_HS_STATE_WAIT_FOR_SERVER_CHANGE_CIPHER_SPEC = 16
      DTLS_HS_STATE_WAIT_FOR_SERVER_FINISHED = 17
      DTLS_HS_STATE_FAILED = 20

      attr_accessor :hs_state

      def initialize config, alert, ccs, lower_layer, tracer = nil
        super "DTLS_HS", lower_layer, tracer
        if !(config.instance_of? Dtls_Config)
          raise "invalid config"
        end
        if !(alert.instance_of? Dtls_Alert)
          raise "invalid alert"
        end
        if !(ccs.instance_of? Dtls_ChangeCipherSpec)
          raise "invalid ccs"
        end
        if !(lower_layer.instance_of? Dtls_Record)
          raise "unexpected lower layer"
        end
        ll_handler_reg Dtls_Record::DTLS_CT_HANDSHAKE, self
        @config = config
        @alert = alert
        @ccs = ccs
        @record = lower_layer
        @tx_message_seq = 0
        @rx_message_seq = 0
        @hs_state = DTLS_HS_STATE_IDLE
        @client_random = random_gen 32
        if (@config.pem_key == nil)
          puts "randomly generating client key"
          @client_ec_key = OpenSSL::PKey::EC.generate("prime256v1")
        else
          puts "using supplied key"
          @client_ec_key = OpenSSL::PKey.read(@config.pem_key)
        end
        @client_ephemeral_ec_key = OpenSSL::PKey::EC.generate("prime256v1")
        @server_cookie = nil
        @server_version = nil
        @server_random = nil
        @session_id = nil
        @cipher_suite = nil
        @compression_method = nil
        @client_certificate_type = nil
        @server_certificate_type = nil
        @ec_point_formats = nil
        @extended_master_secret = false
        @server_public_key = nil
        @server_public_ephemeral_key = nil
        @hs_hash = OpenSSL::Digest::SHA256.new
        @hs_data = ""
      end
      def hs_check condition
        if (!condition)
          @alert.send_fatal_alert(Dtls_Alert::DTLS_ALERT_HANDSHAKE_FAILURE)
          @hs_state = DTLS_HS_STATE_FAILED
          raise "Handshake Failure"
        end
      end
      def hs_send message_type, data
        hs = Et::Frame::DtlsHandshakeHdr.new
        hs.msg_type = message_type
        hs.len = data.length
        hs.message_seq = @tx_message_seq
        @tx_message_seq += 1
        hs.fragment_offset = 0
        hs.fragment_length = data.length
        hs << data
        @hs_hash << hs.to_s
        @hs_data << hs.to_s
        ll_tx Dtls_Record::DTLS_CT_HANDSHAKE, hs
      end
      def send_client_hello cookie = ""
        hs_check((@hs_state == DTLS_HS_STATE_SEND_CLIENT_HELLO_NO_COOKIE) ||
                 (@hs_state == DTLS_HS_STATE_SEND_CLIENT_HELLO_WITH_COOKIE))
        ch = ""
        ch << [Dtls_Record::DTLS_PV_DTLS_1_2].pack("S>")
        if (@client_random.nil?)
          raise "client_random is nil"
        end
        if (@client_random.length != 32)
          raise "client_random length is wrong"
        end
        ch << @client_random.pack("C*") # add client random
        ch << [0].pack("C*") # no session ID
        if (cookie.length >= 256)
          raise "cookie too large"
        end
        ch << [cookie.length].pack("C*")
        if (cookie.length > 0)
          ch << cookie
        end
        ch << [2, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8].pack("S>*") # cipher suite
        ch << [1, TLS_COMPRESSION_NULL].pack("C*") # no compression methods

        extensions = ""
        extensions << [TLS_EXT_CLIENT_CERTIFICATE_TYPE, 2].pack("S>*")
        extensions << [1, TLS_CERT_TYPE_RAW_PUBLIC_KEY].pack("C*")

        extensions << [TLS_EXT_SERVER_CERTIFICATE_TYPE, 2].pack("S>*")
        extensions << [1, TLS_CERT_TYPE_RAW_PUBLIC_KEY].pack("C*")

        extensions << [TLS_EXT_SUPPORTED_GROUPS, 4, 2, TLS_SUPPORTED_GROUP_SECP256R1].pack("S>*")

        extensions << [TLS_EXT_EC_POINT_FORMATS, 2].pack("S>*")
        extensions << [1, TLS_EC_POINT_FORMAT_UNCOMPRESSED].pack("C*")

        extensions << [TLS_EXT_SIGNATURE_ALGORITHMS, 4, 2].pack("S>*")
        extensions << [TLS_HASH_ALGORITHM_SHA256, TLS_SIGNATURE_ALGORITHM_ECDSA].pack("C*")

        if (@config.extended_master_secret != Dtls_Config::EXTENSION_FORCE_OFF)
          extensions << [TLS_EXT_EXTENDED_MASTER_SECRET, 0].pack("S>*")
        end

        ch << [extensions.length].pack("S>")
        ch << extensions

        @hs_hash.reset
        @hs_data = ""

        hs_send DTLS_HS_CLIENT_HELLO, ch
        if (cookie == "")
          #puts "sent client hello"
        else
          #puts "sent client hello with cookie"
        end

        case @hs_state
        when DTLS_HS_STATE_SEND_CLIENT_HELLO_NO_COOKIE
          @hs_state = DTLS_HS_STATE_WAIT_FOR_HELLO_VERIFY_REQUEST
        when DTLS_HS_STATE_SEND_CLIENT_HELLO_WITH_COOKIE
          @hs_state = DTLS_HS_STATE_WAIT_FOR_SERVER_HELLO
        end
      end

      def process_hello_verify_request data
        hs_check(@hs_state == DTLS_HS_STATE_WAIT_FOR_HELLO_VERIFY_REQUEST)
        #puts "processing hello verify request"
        hvr = Et::Frame::DtlsHelloVerifyRequestHdr.new data
        hs_check(hvr.cookie_length == hvr.cookie.length)
        @server_cookie = hvr.cookie
        @hs_state = DTLS_HS_STATE_SEND_CLIENT_HELLO_WITH_COOKIE
      end

      def process_server_hello data
        hs_check((@hs_state == DTLS_HS_STATE_WAIT_FOR_SERVER_HELLO) ||
                 (@hs_state == DTLS_HS_STATE_WAIT_FOR_HELLO_VERIFY_REQUEST))
        #puts "processing server hello"
        @server_version, data = u16_read data
        hs_check(@server_version == Dtls_Record::DTLS_PV_DTLS_1_2)
        @server_random, data = u8_array_read data, 32
        @session_id, data = vbuf_len8_u8_read data
        @cipher_suite, data = u16_read data
        hs_check(@cipher_suite == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
        @compression_method, data = u8_read data
        @client_certificate_type = nil
        @server_certificate_type = nil
        @ec_point_formats = nil
        @extended_master_secret = false
        if (data.size != 0)
          # extensions present
          hs_check(data.size >= 2)
          extensions, data = vbuf_len16_str_read data
          while (extensions.size >= 4)
            ext_code, extensions = u16_read extensions
            ext_data, extensions = vbuf_len16_str_read extensions
            case ext_code
            when TLS_EXT_EC_POINT_FORMATS
              @ec_point_formats, ext_data = vbuf_len8_u8_read ext_data
              hs_check(@ec_point_formats.size == 1)
              hs_check(@ec_point_formats[0] == TLS_EC_POINT_FORMAT_UNCOMPRESSED)
            when TLS_EXT_CLIENT_CERTIFICATE_TYPE
              @client_certificate_type, ext_data = u8_read ext_data
            when TLS_EXT_SERVER_CERTIFICATE_TYPE
              @server_certificate_type, ext_data = u8_read ext_data
            when TLS_EXT_EXTENDED_MASTER_SECRET
              hs_check(ext_data == "")
              @extended_master_secret = true
            else
              hs_check(false)
            end
          end
        end
        hs_check(@client_certificate_type == TLS_CERT_TYPE_RAW_PUBLIC_KEY)
        hs_check(@server_certificate_type == TLS_CERT_TYPE_RAW_PUBLIC_KEY)
        if (@ec_point_formats != nil)
          hs_check(@ec_point_formats.include? TLS_EC_POINT_FORMAT_UNCOMPRESSED)
        end
        if (@config.extended_master_secret == Dtls_Config::EXTENSION_FORCE_OFF)
          hs_check(@extended_master_secret == false)
        end
        if (@config.extended_master_secret == Dtls_Config::EXTENSION_FORCE_ON)
          hs_check(@extended_master_secret == true)
        end
        @hs_state = DTLS_HS_STATE_WAIT_FOR_SERVER_CERTIFICATE
      end

      def process_server_certificate data
        hs_check(@hs_state == DTLS_HS_STATE_WAIT_FOR_SERVER_CERTIFICATE)
        #puts "processing server certificate"
        length_msb, data = u8_read data
        hs_check(length_msb == 0)
        length, data = u16_read data
        hs_check(length == (ASN1_CERTIFICATE_HEADER.length + (2 * 32)))
        asn1_certificate_header, data = u8_array_read data, ASN1_CERTIFICATE_HEADER.length
        hs_check((asn1_certificate_header <=> ASN1_CERTIFICATE_HEADER) == 0)
        pub_x, data = u8_array_read data, 32
        pub_y, data = u8_array_read data, 32
        @server_public_key = raw_public_key_to_ec_key pub_x, pub_y
        @hs_state = DTLS_HS_STATE_WAIT_FOR_SERVER_KEY_EXCHANGE
      end
      
      def process_server_key_exchange data
        hs_check(@hs_state == DTLS_HS_STATE_WAIT_FOR_SERVER_KEY_EXCHANGE)
        #puts "processing server key exchange"
        hash_data = @client_random.pack("C*")
        hash_data << @server_random.pack("C*")
        code, data = u8_read data
        hs_check(code == 3) # 3 == named curve
        hash_data << [code].pack("C")
        named_curve, data = u16_read data
        hs_check(named_curve == TLS_SUPPORTED_GROUP_SECP256R1)
        hash_data << [named_curve].pack("S>")
        ec_point_length, data = u8_read data
        hs_check(ec_point_length == (1 + (2 * DTLS_SECP256R1_KEY_SIZE)))
        hash_data << [ec_point_length].pack("C")
        code, data = u8_read data
        hs_check(code == 4) # 4 == uncompressed
        hash_data << [code].pack("C")
        ephemeral_x, data = u8_array_read data, DTLS_SECP256R1_KEY_SIZE
        hash_data << ephemeral_x.pack("C*")
        ephemeral_y, data = u8_array_read data, DTLS_SECP256R1_KEY_SIZE
        hash_data << ephemeral_y.pack("C*")
        @server_public_ephemeral_key = raw_public_key_to_ec_key ephemeral_x, ephemeral_y
        hash_algo, data = u8_read data
        hs_check(hash_algo == TLS_HASH_ALGORITHM_SHA256)
        sig_algo, data = u8_read data
        hs_check(sig_algo == TLS_SIGNATURE_ALGORITHM_ECDSA)
        signature_r_s, data = vbuf_len16_str_read data
        digest = OpenSSL::Digest::SHA256.new
        hs_check(@server_public_key.verify(digest, signature_r_s, hash_data))
        @hs_state = DTLS_HS_STATE_WAIT_FOR_CERTIFICATE_REQUEST
      end

      def process_server_certificate_request data
        hs_check(@hs_state == DTLS_HS_STATE_WAIT_FOR_CERTIFICATE_REQUEST)
        #puts "processing server certificate request"
        length, data = u8_read data
        hs_check(length == 1)
        code, data = u8_read data
        hs_check(code == TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN)
        length, data = u16_read data
        hs_check(length == 2)
        code, data = u8_read data
        hs_check(code == TLS_HASH_ALGORITHM_SHA256)
        code, data = u8_read data
        hs_check(code == TLS_SIGNATURE_ALGORITHM_ECDSA)
        length, data = u16_read data
        hs_check(length == 0) # 0 = no certificate authorities
        @hs_state = DTLS_HS_STATE_WAIT_FOR_SERVER_HELLO_DONE
      end
      def process_server_hello_done data
        hs_check(@hs_state == DTLS_HS_STATE_WAIT_FOR_SERVER_HELLO_DONE)
        #puts "processing server hello done"
        hs_check(data == "")
        @hs_state = DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE
      end
      def send_client_certificate
        hs_check(@hs_state == DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE)
        msg = [0].pack("C") # length msb == 0
        msg << [ASN1_CERTIFICATE_HEADER.length + (2 * DTLS_SECP256R1_KEY_SIZE)].pack("S>")
        msg << ASN1_CERTIFICATE_HEADER.pack("C*")
        pub_x, pub_y = ec_key_to_raw_public_key @client_ec_key
        msg << pub_x.pack("C*")
        msg << pub_y.pack("C*")
        hs_send DTLS_HS_CERTIFICATE, msg
        #puts "sent client certificate"
        @hs_state = DTLS_HS_STATE_SEND_CLIENT_KEY_EXCHANGE
      end
      def send_client_key_exchange
        hs_check(@hs_state == DTLS_HS_STATE_SEND_CLIENT_KEY_EXCHANGE)
        msg = [1+(2*DTLS_SECP256R1_KEY_SIZE)].pack("C")
        msg << [4].pack("C") # 4 = uncompressed
        pub_x, pub_y = ec_key_to_raw_public_key @client_ephemeral_ec_key
        msg << pub_x.pack("C*")
        msg << pub_y.pack("C*")
        hs_send DTLS_HS_CLIENT_KEY_EXCHANGE, msg
        #puts "sent client key exchange"
        @hs_state = DTLS_HS_STATE_CALC_MASTER_SECRET
      end
      def calc_master_secret
        hs_check(@hs_state == DTLS_HS_STATE_CALC_MASTER_SECRET)
        pre_master_secret = @client_ephemeral_ec_key.dh_compute_key(@server_public_ephemeral_key.public_key)

        # discard ephemeral keys
        @client_ephemeral_ec_key = nil
        @server_public_ephemeral_key = nil

        if (@extended_master_secret)
          #puts "using extended master secret"
          @master_secret = prf(DTLS_MASTER_SECRET_SIZE, pre_master_secret, "extended master secret", @hs_hash.digest)
        else
          #puts "using ordinary master secret"
          @master_secret = prf(DTLS_MASTER_SECRET_SIZE, pre_master_secret, "master secret",
            @client_random.pack("C*"), @server_random.pack("C*"))
        end
        pre_master_secret = nil
        @hs_state = DTLS_HS_STATE_CALC_SECURITY_PARAMS
      end
      def calc_security_params
        hs_check(@hs_state == DTLS_HS_STATE_CALC_SECURITY_PARAMS)
        current_sec_params = @record.current_read_security_parameters
        key_block = prf(DTLS_KEY_BLOCK_SIZE, @master_secret, "key expansion",
            @server_random.pack("C*"), @client_random.pack("C*"))
        @record.pending_security_parameters_set(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
          current_sec_params.epoch + 1, key_block)
        @hs_state = DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE_VERIFY
      end
      def send_client_certificate_verify
        hs_check(@hs_state == DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE_VERIFY)
        digest = OpenSSL::Digest::SHA256.new
        signature = @client_ec_key.sign(digest, @hs_data)
        msg = [TLS_HASH_ALGORITHM_SHA256, TLS_SIGNATURE_ALGORITHM_ECDSA].pack("C*")
        msg << [signature.length].pack("S>")
        msg << signature
        hs_send DTLS_HS_CERTIFICATE_VERIFY, msg
        #puts "sent client certificate verify"
        @hs_state = DTLS_HS_STATE_SEND_CLIENT_CHANGE_CIPHER_SPEC      
      end

      DTLS_FINISHED_SIZE = 12
      def send_client_finished
        hs_check(@hs_state == DTLS_HS_STATE_SEND_CLIENT_FINISHED)
        msg = prf(DTLS_FINISHED_SIZE, @master_secret, "client finished", @hs_hash.digest)
        hs_send DTLS_HS_FINISHED, msg
        #puts "sent client finished"
        @hs_state = DTLS_HS_STATE_WAIT_FOR_SERVER_CHANGE_CIPHER_SPEC
      end

      def process_server_finished data
        hs_check(@hs_state == DTLS_HS_STATE_WAIT_FOR_SERVER_FINISHED)
        #puts "processing server finished"
        expected_msg = prf(DTLS_FINISHED_SIZE, @master_secret, "server finished", @hs_hash.digest)
        if (data == expected_msg)
          #puts "handshake completed successfully"
          @record.set_secure
          @hs_state = DTLS_HS_STATE_IDLE
        else
          @alert.send_fatal_alert Dtls_Alert::DTLS_ALERT_HANDSHAKE_FAILURE
          @record.security_parameters_clear
          @hs_state = DTLS_HS_STATE_FAILED
        end
      end

      def poll_until(&condition)
        count = 20
        while ((count > 0) && (!(condition.call)))
          sleep 0.2
          ll_poll()
          count -= 1
        end
      end

      def do_handshake
        puts "DTLS handshake in progress"
        begin
          hs_check((@hs_state == DTLS_HS_STATE_IDLE) ||
            (@hs_state == DTLS_HS_STATE_FAILED))
          @hs_state = DTLS_HS_STATE_SEND_CLIENT_HELLO_NO_COOKIE
          send_client_hello
          poll_until do
            ((@hs_state == DTLS_HS_STATE_SEND_CLIENT_HELLO_WITH_COOKIE) ||
              (@hs_state == DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE))
          end
          if (@hs_state == DTLS_HS_STATE_SEND_CLIENT_HELLO_WITH_COOKIE)
            hs_check(@server_cookie != nil)
            send_client_hello @server_cookie
            poll_until do
              @hs_state == DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE
            end
          end
          if (@hs_state == DTLS_HS_STATE_SEND_CLIENT_CERTIFICATE)
            send_client_certificate
            send_client_key_exchange
            calc_master_secret
            calc_security_params
            send_client_certificate_verify
            @ccs.send_client_change_cipher_spec
            send_client_finished
            poll_until do
              @record.is_secure
            end
          end
        rescue RuntimeError => e
          puts "do_handshake: caught RuntimeError, #{e.message}"
          @record.security_parameters_clear
          @hs_state = DTLS_HS_STATE_FAILED
        end
        if(@record.is_secure)
          puts "DTLS handshake completed successfully"
        else
          puts "DTLS handshake failed"
        end
      end

      def rx type, data
        if (type != Dtls_Record::DTLS_CT_HANDSHAKE)
          raise "Dtls_Handshake.rx: unexpected content type"
        end
        hs = Et::Frame::DtlsHandshakeHdr.new data
        if (hs.message_seq != @rx_message_seq)
          raise "Dtls_Handshake.rx: unexpected message sequence number"
        end
        @rx_message_seq += 1
        if (hs.fragment_offset != 0)
          raise "Dtls_Handshake.rx: unexpected fragment offset"
        end
        if (hs.len != hs.fragment_length)
          raise "Dtls_Handshake.rx: unexpected fragment length"
        end
        hs_fragment = hs.body
        case hs.msg_type
        when DTLS_HS_SERVER_HELLO
          process_server_hello hs_fragment
        when DTLS_HS_HELLO_VERIFY_REQUEST
          process_hello_verify_request hs_fragment
        when DTLS_HS_CERTIFICATE
          process_server_certificate hs_fragment
        when DTLS_HS_SERVER_KEY_EXCHANGE
          process_server_key_exchange hs_fragment
        when DTLS_HS_CERTIFICATE_REQUEST
          process_server_certificate_request hs_fragment
        when DTLS_HS_SERVER_HELLO_DONE
          process_server_hello_done hs_fragment
        when DTLS_HS_CERTIFICATE_VERIFY
          raise "process certificate verify not implemented"
        when DTLS_HS_CLIENT_KEY_EXCHANGE
          raise "process client key exchange not implemented"
        when DTLS_HS_FINISHED
          process_server_finished hs_fragment
        else
          raise "unexpected handshake message received, msg_type = #{hs.msg_type}"
        end
        @hs_hash << data
        @hs_data << data
      end
    end # Dtls_Handshake

    class Dtls_Alert < Base
      # ALERT level codes defined in RFC 5246, section 7.2
      DTLS_ALERT_LEVEL_WARNING = 1
      DTLS_ALERT_LEVEL_FATAL = 2

      # ALERT description codes defined in RFC 5246, section 7.2
      DTLS_ALERT_CLOSE_NOTIFY = 0
      DTLS_ALERT_UNEXPECTED_MESSAGE = 10
      DTLS_ALERT_BAD_RECORD_MAC = 20
      DTLS_ALERT_DECRYPTION_FAILED_RESERVED = 21
      DTLS_ALERT_RECORD_OVERFLOW = 22
      DTLS_ALERT_DECOMPRESSION_FAILURE = 30
      DTLS_ALERT_HANDSHAKE_FAILURE = 40
      DTLS_ALERT_NO_CERTIFICATE_RESERVED = 41
      DTLS_ALERT_BAD_CERTIFICATE = 42
      DTLS_ALERT_UNSUPPORTED_CERTIFICATE = 43
      DTLS_ALERT_CERTIFICATE_REVOKED = 44
      DTLS_ALERT_CERTIFICATE_EXPIRED = 45
      DTLS_ALERT_CERTIFICATE_UNKNOWN = 46
      DTLS_ALERT_ILLEGAL_PARAMETER = 47
      DTLS_ALERT_UNKNOWN_CA = 48
      DTLS_ALERT_ACCESS_DENIED = 49
      DTLS_ALERT_DECODE_ERROR = 50
      DTLS_ALERT_DECRYPT_ERROR = 51
      DTLS_ALERT_EXPORT_RESTRICTION_RESERVED = 60
      DTLS_ALERT_PROTOCOL_VERSION = 70
      DTLS_ALERT_INSUFFICIENT_SECURITY = 71
      DTLS_ALERT_INTERNAL_ERROR = 80
      DTLS_ALERT_USER_CANCELED = 90
      DTLS_ALERT_NO_RENEGOTIATION = 100
      DTLS_ALERT_UNSUPPORTED_EXTENSION = 110

      def initialize lower_layer, tracer = nil
        super "DTLS_ALERT", lower_layer, tracer
        if !(lower_layer.instance_of? Dtls_Record)
          raise "unexpected lower layer"
        end
        @rec = lower_layer
        ll_handler_reg Dtls_Record::DTLS_CT_ALERT, self
      end
      def level_to_string level
        result = "UNKNOWN_LEVEL"
        case level
        when DTLS_ALERT_LEVEL_WARNING
          result = "WARNING"
        when DTLS_ALERT_LEVEL_FATAL
          result = "FATAL"
        end
        result << "(#{level.inspect})"
        return result
      end
      def description_to_string description
        result = "UNKNOWN_DESCRIPTION"
        case description
        when DTLS_ALERT_CLOSE_NOTIFY
          result = "CLOSE_NOTIFY"
        when DTLS_ALERT_UNEXPECTED_MESSAGE
          result = "UNEXPECTED_MESSAGE"
        when DTLS_ALERT_BAD_RECORD_MAC
          result = "BAD_RECORD_MAC"
        when DTLS_ALERT_DECRYPTION_FAILED_RESERVED
          result = "DECRYPTION_FAILED_RESERVED"
        when DTLS_ALERT_RECORD_OVERFLOW
          result = "RECORD_OVERFLOW"
        when DTLS_ALERT_DECOMPRESSION_FAILURE
          result = "DECOMPRESSION_FAILURE"
        when DTLS_ALERT_HANDSHAKE_FAILURE
          result = "HANDSHAKE_FAILURE"
        when DTLS_ALERT_NO_CERTIFICATE_RESERVED
          result = "NO_CERTIFICATE_RESERVED"
        when DTLS_ALERT_BAD_CERTIFICATE
          result = "BAD_CERTIFICATE"
        when DTLS_ALERT_UNSUPPORTED_CERTIFICATE
          result = "UNSUPPORTED_CERTIFICATE"
        when DTLS_ALERT_CERTIFICATE_REVOKED
          result = "CERTIFICATE_REVOKED"
        when DTLS_ALERT_CERTIFICATE_EXPIRED
          result = "CERTIFICATE_EXPIRED"
        when DTLS_ALERT_CERTIFICATE_UNKNOWN
          result = "CERTIFICATE_UNKNOWN"
        when DTLS_ALERT_ILLEGAL_PARAMETER
          result = "ILLEGAL_PARAMETER"
        when DTLS_ALERT_UNKNOWN_CA
          result = "UNKNOWN_CA"
        when DTLS_ALERT_ACCESS_DENIED
          result = "ACCESS_DENIED"
        when DTLS_ALERT_DECODE_ERROR
          result = "DECODE_ERROR"
        when DTLS_ALERT_DECRYPT_ERROR
          result = "DECRYPT_ERROR"
        when DTLS_ALERT_EXPORT_RESTRICTION_RESERVED
          result = "EXPORT_RESTRICTION_RESERVED"
        when DTLS_ALERT_PROTOCOL_VERSION
          result = "PROTOCOL_VERSION"
        when DTLS_ALERT_INSUFFICIENT_SECURITY
          result = "INSUFFICIENT_SECURITY"
        when DTLS_ALERT_INTERNAL_ERROR
          result = "INTERNAL_ERROR"
        when DTLS_ALERT_USER_CANCELED
          result = "USER_CANCELED"
        when DTLS_ALERT_NO_RENEGOTIATION
          result = "NO_RENEGOTIATION"
        when DTLS_ALERT_UNSUPPORTED_EXTENSION
          result = "UNSUPPORTED_EXTENSION"
        end
        result << "(#{description.inspect})"
        return result
      end
      def send_alert level, description
        alert = Et::Frame::DtlsAlertHdr.new
        alert.level = level
        alert.description = description
        ll_tx Dtls_Record::DTLS_CT_ALERT, alert
      end
      def send_fatal_alert description
        send_alert DTLS_ALERT_LEVEL_FATAL, description
      end
      def rx type, data
        if type != Dtls_Record::DTLS_CT_ALERT
          raise "Dtls_Alert: unexpected record type"
        end
        alert = Et::Frame::DtlsAlertHdr.new data
        if ((alert.level == DTLS_ALERT_LEVEL_FATAL) || (alert.description == DTLS_ALERT_CLOSE_NOTIFY))
          puts "Dtls_Alert.rx: #{level_to_string alert.level} #{description_to_string alert.description}"
          @rec.security_parameters_clear
          raise "received fatal or close alert"
        end
      end
    end # Dtls_Alert

    class Lib_CCM
      CCM_C = "ccm.c"
      CCM_RIJNDAEL_C = "rijndael.c"
      CCM_RIJNDAEL_H = "rijndael.h"
      CCM_O = "ccm.o"
      CCM_RIJNDAEL_O = "rijndael.o"
      CCM_SO = "ccm.so"

      CCM_M = 8

      def initialize
        # NOTE: relative directories don't always work since File.pwd may be a different directory
        #       therefor construct the absolute directory from the location of this file.
        local_dir = File.dirname(__FILE__)
        local_dir = local_dir.chomp("handler") + "ccm/"
        if (!(Dir.exist?(local_dir)))
          raise "make_ccm_library: ccm directory not found, looking for #{local_dir.inspect}"
        end

        @ccm_c = local_dir + CCM_C
        @ccm_rijndael_c = local_dir + CCM_RIJNDAEL_C
        @ccm_rijndael_h = local_dir + CCM_RIJNDAEL_H
        @ccm_o = local_dir + CCM_O
        @ccm_rijndael_o = local_dir + CCM_RIJNDAEL_O
        @ccm_so = local_dir + CCM_SO

        make_ccm_library

        @lib_ccm = Fiddle.dlopen(@ccm_so)

        @ccm_test = Fiddle::Function.new(
          @lib_ccm["ccm_test"],
          [],
          Fiddle::TYPE_INT
        )
        if (@ccm_test.call() != 1)
          raise "ccm test failed"
        end

        @ccm_encrypt = Fiddle::Function.new(
          @lib_ccm["ccm_encrypt"],
          [Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP],
          Fiddle::TYPE_INT
        )

        @ccm_decrypt = Fiddle::Function.new(
          @lib_ccm["ccm_decrypt"],
          [Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP,
           Fiddle::TYPE_VOIDP],
          Fiddle::TYPE_INT
        )

      end

      def make_ccm_library
        if !(File.file?(@ccm_c))
          raise "#{@ccm_c} not found"
        end
        if !(File.file?(@ccm_rijndael_c))
          raise "#{@ccm_rijndael_c} not found"
        end
        if !(File.file?(@ccm_rijndael_h))
          raise "#{@ccm_rijndael_h} not found"
        end

        if ((!(File.file?(@ccm_so))) ||
          (File.mtime(@ccm_c) > File.mtime(@ccm_so)) ||
          (File.mtime(@ccm_rijndael_c) > File.mtime(@ccm_so)) ||
          (File.mtime(@ccm_rijndael_h) > File.mtime(@ccm_so)))
          # clean up old files
          if (File.file?(@ccm_o))
            File.delete(@ccm_o)
          end
          if (File.file?(@ccm_rijndael_o))
            File.delete(@ccm_rijndael_o)
          end
          if (File.file?(@ccm_so))
            File.delete(@ccm_so)
          end
          puts "Compiling CCM library"
          puts `gcc -Werror -c -fPIC -o #{@ccm_o} #{@ccm_c}`
          puts `gcc -Werror -c -fPIC -o #{@ccm_rijndael_o} #{@ccm_rijndael_c}`
          puts `gcc -Werror -shared -o #{@ccm_so} #{@ccm_o} #{@ccm_rijndael_o}`
        end
        
        if !(File.file?(@ccm_so))
          raise "Failed to create CCM library"
        end
      end

      def str_to_vbuf(data)
        if (data == nil)
          raise "str_to_vbuf: data == nil"
        end
        size_of_int = Fiddle::CStructEntity::size([Fiddle::TYPE_INT])
        size_of_voidp = Fiddle::CStructEntity::size([Fiddle::TYPE_VOIDP])
        size_of_vbuf = Fiddle::CStructEntity.size([Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP])
        ptr = Fiddle::Pointer.malloc(size_of_vbuf)
        ptr[0, size_of_int] = [data.length].pack("L")
        data_ptr = Fiddle::Pointer[data]
        pack_code = "Q"
        if (size_of_voidp == 4)
          pack_code = "L"
        end
        ptr[size_of_vbuf - size_of_voidp, size_of_voidp] = [data_ptr.to_i].pack(pack_code)
        return ptr
      end

      def vbuf_to_str(vbuf)
        size_of_int = Fiddle::CStructEntity::size([Fiddle::TYPE_INT])
        size_of_voidp = Fiddle::CStructEntity::size([Fiddle::TYPE_VOIDP])
        size_of_vbuf = Fiddle::CStructEntity.size([Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP])
        vbuf_length = vbuf[0, size_of_int].unpack("L")[0]
        pack_code = "Q"
        if (size_of_voidp == 4)
          pack_code = "L"
        end
        vbuf_data_ptr = vbuf[size_of_vbuf - size_of_voidp, size_of_voidp].unpack(pack_code)[0]
        vbuf_data = Fiddle::Pointer.new(vbuf_data_ptr, vbuf_length)
        return vbuf_data[0, vbuf_length]
      end
      
      def create_empty_vbuf(size)
        if (size < 1)
          raise "create_empty_vbuf: size < 1"
        end
        size_of_int = Fiddle::CStructEntity::size([Fiddle::TYPE_INT])
        size_of_voidp = Fiddle::CStructEntity::size([Fiddle::TYPE_VOIDP])
        size_of_vbuf = Fiddle::CStructEntity.size([Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP])
        ptr = Fiddle::Pointer.malloc(size_of_vbuf)
        ptr[0,size_of_int] = [size].pack("L!")
        data_ptr = Fiddle::Pointer.malloc(size)
        pack_code = "Q"
        if (size_of_voidp == 4)
          pack_code = "L"
        end
        ptr[size_of_vbuf - size_of_voidp, size_of_voidp] = [data_ptr.to_i].pack(pack_code)
        return ptr
      end

      def encrypt(key, nonce, aad, msg_in)
        key_vbuf = str_to_vbuf(key)
        nonce_vbuf = str_to_vbuf(nonce)
        aad_vbuf = str_to_vbuf(aad)
        msg_in_vbuf = str_to_vbuf(msg_in)
        msg_out_vbuf = create_empty_vbuf(msg_in.length + CCM_M)
        result = @ccm_encrypt.call(key_vbuf, nonce_vbuf, aad_vbuf, msg_in_vbuf, msg_out_vbuf)
        if (result == 0)
          raise "encryption failed"
        end
        result = vbuf_to_str(msg_out_vbuf)
        return result
      end

      def decrypt(key, nonce, aad, msg_in)
        if (msg_in.length <= CCM_M)
          raise "msg_in.length <= CCM_M"
        end
        key_vbuf = str_to_vbuf(key)
        nonce_vbuf = str_to_vbuf(nonce)
        aad_vbuf = str_to_vbuf(aad)
        msg_in_vbuf = str_to_vbuf(msg_in)
        msg_out_vbuf = create_empty_vbuf(msg_in.length - CCM_M)
        result = @ccm_decrypt.call(key_vbuf, nonce_vbuf, aad_vbuf, msg_in_vbuf, msg_out_vbuf)
        if (result == 0)
          raise "decryption failed"
        end
        return vbuf_to_str(msg_out_vbuf)
      end
    end

    class Dtls_Security_Parameters
      attr_reader :cipher_type, :epoch

      def initialize lib_ccm, cipher_type, epoch, key_block=nil
        if (lib_ccm == nil)
          raise "lib_ccm == nil"
        end
        
        if !(lib_ccm.instance_of? Lib_CCM)
          raise "unknown lib_ccm"
        end

        @lib_ccm = lib_ccm
        @cipher_type = cipher_type
        @epoch = epoch
        if (key_block != nil)
          if (key_block.size != Dtls_Handshake::DTLS_KEY_BLOCK_SIZE)
            raise "invalid key block size"
          end
        end
        @key_block = key_block
        @next_tx_sequence_number = 0
        @next_rx_sequence_number = 0
      end
      def next_tx_sequence_number_get
        result = @next_tx_sequence_number
        @next_tx_sequence_number += 1
        return result
      end
      def next_rx_sequence_number_get
        result = @next_rx_sequence_number
        @next_rx_sequence_number += 1
        return result
      end
      def client_write_key
        if (@key_block == nil)
          raise "key_block == nil"
        end
        if (@key_block.length != Dtls_Handshake::DTLS_KEY_BLOCK_SIZE)
          raise "wrong length for key_block"
        end
        return @key_block[0, Dtls_Handshake::DTLS_ENC_KEY_SIZE]
      end
      def server_write_key
        if (@key_block == nil)
          raise "key_block == nil"
        end
        if (@key_block.length != Dtls_Handshake::DTLS_KEY_BLOCK_SIZE)
          raise "wrong length for key_block"
        end
        return @key_block[Dtls_Handshake::DTLS_ENC_KEY_SIZE, Dtls_Handshake::DTLS_ENC_KEY_SIZE]
      end
      def client_write_iv
        if (@key_block == nil)
          raise "key_block == nil"
        end
        if (@key_block.length != Dtls_Handshake::DTLS_KEY_BLOCK_SIZE)
          raise "wrong length for key_block"
        end
        return @key_block[2 * Dtls_Handshake::DTLS_ENC_KEY_SIZE, Dtls_Handshake::DTLS_FIXED_IV_SIZE]
      end
      def server_write_iv
        if (@key_block == nil)
          raise "key_block == nil"
        end
        if (@key_block.length != Dtls_Handshake::DTLS_KEY_BLOCK_SIZE)
          raise "wrong length for key_block"
        end
        return @key_block[(2 * Dtls_Handshake::DTLS_ENC_KEY_SIZE) + Dtls_Handshake::DTLS_FIXED_IV_SIZE, Dtls_Handshake::DTLS_FIXED_IV_SIZE]
      end

      def encrypt record
        result = nil
        case @cipher_type
        when Dtls_Handshake::TLS_NULL_WITH_NULL_NULL
          # nothing to do
          result = record
        when Dtls_Handshake::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
          if (@key_block == nil)
            raise "key_block == nil"
          end
          key = client_write_key
          nonce = client_write_iv
          explicit_iv = [@epoch].pack("S>")
          seq_num = [record.sequence_number].pack("Q>")
          seq_num_high_16 = seq_num[0, 2]
          if (seq_num_high_16.unpack("S>")[0] != 0)
            # if the sequence number ever gets this high (unlikely)
            #  I believe we should do a new handshake to
            #  reset the sequence number which also
            #  increments the epoch
            raise "record sequence number too high"
          end
          seq_num_low_48 = seq_num[2, 6] # low 48 bits
          explicit_iv << seq_num_low_48
          nonce << explicit_iv

          aad = [@epoch].pack("S>")
          aad << seq_num_low_48
          aad << [record.content_type].pack("C")
          aad << [record.version].pack("S>")
          aad << [record.body.length].pack("S>")

          record.body = explicit_iv + @lib_ccm.encrypt(key, nonce, aad, record.body)
          record.fragment_length = record.body.length
          result = record
        else
          raise "unknown encryption method"
        end
        return result
      end
      def decrypt record
        result = nil
        case @cipher_type
        when Dtls_Handshake::TLS_NULL_WITH_NULL_NULL
          # nothing to do
          result = record
        when Dtls_Handshake::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
          if (@key_block == nil)
            raise "key_block == nil"
          end
          body = record.body
          if (body.length < (8 + Lib_CCM::CCM_M))
            raise "body.length < 8"
          end
          key = server_write_key
          explicit_iv = body[0, 8]
          nonce = server_write_iv + explicit_iv
          body = body[8, body.length]
          seq_num = [record.sequence_number].pack("Q>")
          seq_num_high_16 = seq_num[0, 2]
          if (seq_num_high_16.unpack("S>")[0] != 0)
            # if the sequence number ever gets this high (unlikely)
            #  I believe we should do a new handshake to
            #  reset the sequence number which also
            #  increments the epoch
            raise "record sequence number too high"
          end
          seq_num_low_48 = seq_num[2, 6] # low 48 bits
          aad = explicit_iv
          aad << [record.content_type].pack("C")
          aad << [record.version].pack("S>")
          aad << [body.length - Lib_CCM::CCM_M].pack("S>")

          record.body = @lib_ccm.decrypt(key, nonce, aad, body)
          record.fragment_length = record.body.length
          result = record
        else
          raise "unknown encryption method"
        end
        return result
      end

    end

    class Dtls_Record < Base

      # Record Content Type codes
      DTLS_CT_CHANGE_CIPHER_SPEC = 20
      DTLS_CT_ALERT = 21
      DTLS_CT_HANDSHAKE = 22
      DTLS_CT_APPLICATION_DATA = 23

      # Protocol Version codes
      DTLS_PV_DTLS_1_0 = 0xFEFF
      DTLS_PV_DTLS_1_2 = 0xFEFD

      attr_reader :current_read_security_parameters

      def initialize lower_layer, tracer = nil
        super "DTLS_REC", lower_layer, tracer
        # assuming lower layer is mup1
        ll_handler_reg Mup1::MUP1_CB_DTLS, self

        if (!OpenSSL::Cipher.ciphers.include? "aes-128-ccm")
          raise "missing AES-128-CCM"
        end

        @lib_ccm = Lib_CCM.new

        security_parameters_clear
      end
      def security_parameters_clear
        @is_secure = false
        nosec_parameters = Dtls_Security_Parameters.new(@lib_ccm, Dtls_Handshake::TLS_NULL_WITH_NULL_NULL, 0)
        @current_read_security_parameters = nosec_parameters
        @current_write_security_parameters = nosec_parameters
        @pending_read_security_parameters = nil
        @pending_write_security_parameters = nil
      end
      def pending_security_parameters_set(cipher_type, epoch, key_block=nil)
        security_parameters = Dtls_Security_Parameters.new(@lib_ccm, cipher_type, epoch, key_block)
        if (@pending_read_security_parameters != nil)
          raise "pending read security parameters already set"
        end
        if (@pending_write_security_parameters != nil)
          raise "pending write security parameters already set"
        end
        @pending_read_security_parameters = security_parameters
        @pending_write_security_parameters = security_parameters
      end
      def pending_write_security_params_activate
        if (@pending_write_security_parameters == nil)
          raise "pending_write_security_parameters == nil"
        end
        @current_write_security_parameters = @pending_write_security_parameters
        @pending_write_security_parameters = nil
      end
      def pending_read_security_params_activate
        if (@pending_read_security_parameters == nil)
          raise "pending_read_security_parameters == nil"
        end
        @current_read_security_parameters = @pending_read_security_parameters
        @pending_read_security_parameters = nil
      end

      def is_secure
        return @is_secure
      end
      def set_secure
        @is_secure = true
      end
      def set_alert alert
        @alert = alert
      end
      def tx content_type, data
        sec_params = @current_write_security_parameters
        if (sec_params == nil)
          raise "sec_params == nil"
        end
        rec = Et::Frame::DtlsRecordHdr.new
        rec.content_type = content_type
        rec.version = DTLS_PV_DTLS_1_2
        rec.epoch = sec_params.epoch
        rec.sequence_number = sec_params.next_tx_sequence_number_get
        rec.fragment_length = data.length
        rec << data
        rec = sec_params.encrypt(rec)
        ll_tx 0x64, rec
      end
      def poll
        ll_poll()
      end
      def rx type, data
        sec_params = @current_read_security_parameters
        if (sec_params == nil)
          raise "sec_params == nil"
        end

        rec = Et::Frame::DtlsRecordHdr.new data
        #puts "Dtls_Record.rx: rec = #{rec.inspect}"
        if (rec.version != DTLS_PV_DTLS_1_2) && (rec.version != DTLS_PV_DTLS_1_0)
          if !@alert.nil?
            @alert.send_fatal_alert(Dtls_Alert::DTLS_ALERT_PROTOCOL_VERSION)
          end
        end
        if (rec.epoch != sec_params.epoch)
          raise "unexpected epoch"
        end
        if (rec.sequence_number != sec_params.next_rx_sequence_number_get)
          # out of order frames not possible with mup1
          raise "unexpected sequence number"
        end
        rec = sec_params.decrypt rec
        handler_call_rx rec.content_type, rec.body
      end
    end # Dtls_Record
  end # Handler
end # Et

def Create_Dtls_Handlers config, lower_layer, tracer = nil
  if !config.instance_of? Et::Handler::Dtls_Config
    raise "invalid config"
  end
  record_layer = Et::Handler::Dtls_Record.new lower_layer, tracer
  ccs_protocol = Et::Handler::Dtls_ChangeCipherSpec.new record_layer, tracer
  alert_protocol = Et::Handler::Dtls_Alert.new record_layer, tracer
  record_layer.set_alert(alert_protocol)
  handshake_protocol = Et::Handler::Dtls_Handshake.new config, alert_protocol, ccs_protocol, record_layer, tracer
  ccs_protocol.handshake_set handshake_protocol
  app_protocol = Et::Handler::Dtls_Application.new handshake_protocol, record_layer, tracer
  return app_protocol
end

def u8_read data
  return data.unpack("C")[0], data[1, data.size]
end

def u16_read data
  return data.unpack("S>")[0], data[2, data.size]
end

def u32_read data
  return data.unpack("L>")[0], data[4, data.size]
end

def u8_array_read data, length
  return data.unpack("C" * length), data[length, data.size]
end

def vbuf_len8_u8_read data
  len = data.unpack("C")[0]
  buf_start = data[1,data.size]
  return buf_start.unpack("C" * len), buf_start[len, buf_start.size]
end

def vbuf_len16_str_read data
  len = data.unpack("S>")[0]
  buf_start = data[2, data.size]
  return buf_start[0, len], buf_start[len, buf_start.size]
end

def random_gen length
  result = []
  index = 0
  while index < length do
    result << rand(2**8)
    index += 1
  end
  return result
end

def openssl_bn_init data
  # assuming data is a byte array
  data_str = data.pack("C*")
  data_hex_str = data_str.each_byte.map do |b|
    n0 = b / 16
    n1 = b % 16
    n0.to_s(16) + n1.to_s(16)
  end.join
  bn = OpenSSL::BN.new(data_hex_str, 16)
  return bn
end

def raw_public_key_to_ec_key pub_x, pub_y
  # assuming pub_x, and pub_y are each 32 byte arrays
  object_id_public_key = OpenSSL::ASN1::ObjectId.new("id-ecPublicKey")
  object_id_prime256v1 = OpenSSL::ASN1::ObjectId.new("prime256v1")
  seq_object_id = OpenSSL::ASN1::Sequence.new([object_id_public_key, object_id_prime256v1])
  key_string = [4].pack("C")
  key_string << pub_x.pack("C*")
  key_string << pub_y.pack("C*")
  asn1_bit_string = OpenSSL::ASN1::BitString.new(key_string)
  asn1_pub_key = OpenSSL::ASN1::Sequence.new([seq_object_id, asn1_bit_string])
  return OpenSSL::PKey::EC.new(asn1_pub_key.to_der)
end

def ec_key_to_raw_private_key ec_key
  data = ec_key.private_key.to_s(0)
  length, data = u32_read data
  if (length > 33)
    raise "length too long"
  end
  if (length == 33)
    zero, data = u8_read data
    if (zero != 0)
      raise "expected zero msb"
    end
    length -= 1
  end
  if (length != 32)
    raise "length != 32"
  end
  result = data.unpack("C*")
  if (result.length != 32)
    raise "result.length = #{result.length.inspect}"
  end
  return result
end

def ec_key_to_raw_public_key ec_key
  data = ec_key.public_key.to_octet_string(:uncompressed)
  raise "unexpected data size" if (data.length != 65)
  code, data = u8_read data
  raise "expected uncompressed" if (code != 4)
  pub_x, data = u8_array_read data, 32
  pub_y, data = u8_array_read data, 32
  return pub_x, pub_y
end

def prf output_length, key, label=nil, random1=nil, random2=nil
  output = ""
  a = nil
  while (output_length > 0) do
    digest = OpenSSL::Digest::SHA256.new
    hmac = OpenSSL::HMAC.new(key, digest)
    if (a == nil)
      if (label != nil)
        hmac << label
      end
      if (random1 != nil)
        hmac << random1
      end
      if (random2 != nil)
        hmac << random2
      end
    else
      hmac << a
    end
    a = hmac.digest
    
    digest = OpenSSL::Digest::SHA256.new
    hmac = OpenSSL::HMAC.new(key, digest)
    hmac << a
    if (label != nil)
      hmac << label
    end
    if (random1 != nil)
      hmac << random1
    end
    if (random2 != nil)
      hmac << random2
    end
    output_block = hmac.digest
    if (output_block.length != 32)
      raise "output_block.length != 32"
    end
    if (output_length < output_block.length)
      output_block = output_block[0, output_length]
    end
    output << output_block
    output_length -= output_block.length
  end
  a = nil
  return output
end

def pem_ec_key_gen
  ec_key = OpenSSL::PKey::EC.generate("prime256v1")
  return ec_key.to_pem
end