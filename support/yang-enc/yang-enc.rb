#!/usr/bin/env ruby

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require_relative './yang-utils.rb'
require_relative './yang-schema.rb'
require 'yaml'
require 'json'
require 'cbor-pure'
require 'json_schemer'
require 'base64'
require 'optparse'
require 'open3'
require 'pp'

def main
    top = __dir__  # Script location
    2.times do     # Assume script is located two dirs above repository root
        top = File.dirname(top)
    end
    # top is now the absolute repository root

    opt_parser = OptionParser.new do |opts|
        opts.banner = """Usage: yang-enc [subcommand] [options]

    Subcommands:
    conv                             Convert JSON/YAML to CBOR or CBOR to JSON/YAML
    schema                           Convert YANG files to JSON schema
    Options:"""
        opts.on("-h", "--help", "Show this message") do
            puts opts
            exit
        end
    end

    input_format = 'yaml'
    output_format = 'cbor'
    content_format = 'yang'

    conv_parser = OptionParser.new do |opts|
        opts.banner = """Usage: yang-enc conv [options] [<data file>] [<sid files> <yang files>]
If no data file, read from STDIN.
If no sid and yang files, the default schema is used.

    Options:"""
        opts.on("-i", "--input yaml|json|cbor", ["yaml", "json", "cbor"],
                "Input file format. Default is '#{input_format}'") do |i|
            input_format = i
        end

        opts.on("-o", "--output yaml|json|cbor", ["yaml", "json", "cbor"],
                "Output file format. Default is '#{output_format}'") do |o|
            output_format = o
        end

        opts.on("-c", "--content yang|fetch|ipatch|get|put|post", ["yang", "fetch", "ipatch", "get", "put", "post"],
                "Input content format. Default is '#{content_format}'",
                "yang:   Content is a YANG data tree as defined in RFC 7950 section 3.",
                "fetch:  Content is one or more FETCH requests or responses.",
                "ipatch: Content is one or more iPATCH requests.",
                "get:    Content is a GET response (alias for yang).",
                "put:    Content is a PUT request (alias for yang).",
                "post:   Content is a POST request or response (for RPCs and actions) .") do |c|
            content_format = c
        end

        opts.on("-h", "--help", "Show this message") do
            puts opts
            exit
        end
    end

    schema_parser = OptionParser.new do |opts|
        opts.banner = """Usage: yang-enc schema [options] [<yang files>]
If no yang files, the default schema is used.

    Options:"""
        opts.on("-h", "--help", "Show this message") do
            puts opts
            exit
        end
    end

    opt_parser.order!(ARGV)
    subcmd = ARGV.shift

    yangs = ARGV.select {|x| x.end_with? '.yang'}
    yangs.each {|e| ARGV.delete(e) } # Remove .yang files from ARGV to prevent ARGF from reading them
    sids  = ARGV.select {|x| x.end_with? '.sid'}
    sids.each {|e| ARGV.delete(e) } # Remove .sid files from ARGV to prevent ARGF from reading them

    case subcmd

    when 'conv'
        conv_parser.parse!(ARGV)
        abort("Too many arguments!") if ARGV.size > 1

        case input_format

        when 'yaml'
            input_data = YAML.load(ARGF.read)

        when 'json'
            input_data = JSON.parse(ARGF.read)

        when 'cbor'
            ARGF.binmode
            input_data = CBOR.decode_seq(ARGF.read)

        else
            abort("Unknown file format #{input_format}")

        end
        if yangs.empty? and sids.empty?
            schema = yang_schema_get # Use cached schema
        elsif yangs.any? and sids.any?
            schema = generate_yang_schema("#{top}/docs/sw_refs/yang", yangs, sids)
        else
            abort("Missing .yang or .sid files!")
        end

    when 'schema'
        schema_parser.parse!(ARGV)
        abort("Too many arguments!") if ARGV.size > 0
        abort(".sid files not allowed!") if sids.any?
        if yangs.empty?
            schema = yang_schema_get # Use cached schema
        else
            schema = generate_yang_schema("#{top}/docs/sw_refs/yang", yangs, sids)
        end

    else
        abort("Unrecognized subcommand: #{subcmd}")

    end

    case subcmd

    when 'conv'
        case [input_format, output_format]

        when ['json', 'cbor'], ['yaml', 'cbor']
            STDOUT.binmode
            STDOUT.write(json_seq2cbor(schema, input_data, content_format))

        when ['cbor', 'json']
            puts JSON.pretty_generate(cbor_seq2json(schema, input_data, content_format))

        when ['cbor', 'yaml']
            puts cbor_seq2json(schema, input_data, content_format).to_yaml

        when ['json', 'yaml'], ['yaml', 'yaml']
            puts input_data.to_yaml

        when ['yaml', 'json'], ['json', 'json']
            puts JSON.pretty_generate(input_data)

        when ['cbor', 'cbor']
            STDOUT.binmode
            input_data.each { |i| STDOUT.write(CBOR.encode(i)) }

        end

    when 'schema'
        puts JSON.pretty_generate(to_json_schema(schema, 'yang'))

    end
end

def json2cbor_hash(node, json, content_format)
    result = {}
    json.each do |key, value|
        child = node.substms.find { |s| s.arg == key }
        if child.nil?
            STDERR.puts "Can't find #{key} in #{node.kw} #{node.arg}, skipping..."
            next
        elsif child.sid.nil?
            STDERR.puts "#{child.kw} #{child.arg} in #{node.kw} #{node.arg}: missing SID, skipping..."
            next
        end
        delta_sid = child.sid - node.sid
        result[delta_sid] = json2cbor(child, value, content_format)
    end
    return result
end

def json2cbor_array(node, json, content_format)
    return json.map do |entry|
        result = {}
        entry.each do |key, value|
            child = node.substms.find { |s| s.arg == key }
            if child.nil?
                STDERR.puts "Can't find #{key} in #{node.kw} #{node.arg}, skipping..."
                next
            elsif child.sid.nil?
                STDERR.puts "#{child.kw} #{child.arg} in #{node.kw} #{node.arg}: missing SID, skipping..."
                next
            end
            delta_sid = child.sid - node.sid
            result[delta_sid] = json2cbor(child, value, content_format)
        end
        result
    end
end

def json2cbor(node, json, content_format)
    node.sid = 0 if node.kw == 'module'
    case node.kw
    when 'module', 'container', 'input', 'output'
        result = {}
        if json.is_a? Hash
            result = json2cbor_hash(node, json, content_format)
        else
            STDERR.puts "In #{node.kw} #{node.arg}: expected Hash but found #{json.class}"
        end
        result

    when 'list'
        result = []
        if ['fetch', 'ipatch'].include?(content_format)
            if json.is_a? Array
                result = json2cbor_array(node, json, content_format)
            elsif json.is_a? Hash
                result = json2cbor_hash(node, json, content_format)
            else
                STDERR.puts "In #{node.kw} #{node.arg}: expected Array or Hash but found #{json.class}"
            end
        else
            if json.is_a? Array
                result = json2cbor_array(node, json, content_format)
            else
                STDERR.puts "In #{node.kw} #{node.arg}: expected Array but found #{json.class}"
            end
        end
        result

    when 'leaf'
        return type2cbor(node.type, json)

    when 'leaf-list'
        return json.map {|entry| type2cbor(node.type, entry)}

    when 'anydata'
        if node.arg == 'board:factory_default_config'
            ds_schema = yang_schema_get
            return json2cbor(ds_schema, json, content_format)
        end

    when 'rpc', 'action'
        node.substms.each do |child|
            if json and child.kw == json.keys[0] and json.values[0].is_a? Hash and json.values[0].any?
                # Child SIDs of 'input'/'output' must be relative to the SID in 'rpc'/'action'.
                # See core-comi-19 section 3.5.
                # TODO jea: Replace with RFC xxxx above when ready
                saved_sid = child.sid # Save child.sid for later restore
                child.sid = node.sid
                result = json2cbor(child, json.values[0], content_format)
                child.sid = saved_sid # Restore child.sid
                return result
            end
        end
        nil # No 'input'/'output' found

    else
        abort("Invalid keyword #{node.kw}")
    end
end

def type2cbor(type, value, schema = nil, unions = [])
    begin
        case type.name

        when 'enumeration'
            if unions.empty?
                type.enums[value].value
            else
                CBOR::Tagged.new(44, value) # See RFC 9254 section 6.6.
            end

        when 'bits'
            # See RFC 9254 section 6.7.
            if unions.empty?
                encoding = []
                bytes    = []
                offset   = 0
                stop     = 0

                value.split(' ').map {|bit| type.bits[bit].position}.sort!.each do |pos|
                    # Loop invariant: offset <= pos
                    if pos < stop
                        if bytes.empty?
                            bytes << 0
                            stop += 8
                        end
                        bytes[-1] |= 1 << (pos - offset)
                    else
                        delta = (pos - stop) / 8

                        if delta == 0
                            offset = stop
                            bytes << (1 << (pos - offset))
                            stop += 8
                        else
                            encoding << bytes.pack('C*') if !bytes.empty?
                            encoding << delta
                            offset = stop + delta * 8
                            bytes = [1 << (pos - offset)]
                            stop = offset + 8
                        end
                    end
                end

                encoding << bytes.pack('C*') if !bytes.empty?
                return encoding.length == 1 ? encoding[0] : encoding
            else
                CBOR::Tagged.new(43, value)
            end

        when 'binary'
            Base64.decode64 value # See RFC 9254 section 6.8.

        when 'decimal64'
            begin
                significand, fraction = value.split '.'
                fraction = (fraction or '').ljust(type.fraction_digits, '0')
                # See RFC 9254 section 6.3.
                str = (significand or '') + fraction
                _ = Integer(str) # Raise if str is not a valid integer
                int = str.to_i(10)
                CBOR::Tagged.new(4, [-type.fraction_digits, int])
            rescue ArgumentError
                abort("Invalid decimal64 value #{value}")
            end

        when 'int64', 'uint64'
            Integer(value) # See RFC 7951 section 6.1.

        when 'leafref'
            type2cbor(type.deref.type, value, schema, unions)

        when 'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32'
            value

        when 'union'
            t = type.members.find {|t| match_type_json(t, value)}
            # One type is guaranteed to match because the input has been schema validated.
            unions << type
            result = type2cbor(t, value, schema, unions)
            unions.pop
            result

        when 'empty'
            nil

        when 'identityref'
            sid = nil
            # See RFC 9254 section 6.10 and 6.10.1.
            type.deref.map(&:derived_from).reduce(:&).each do |id|
                sid = id.sid if id.mod == type.mod and id.name == value
                sid = id.sid if value =~ /(.+):(.+)/ and $1 == id.mod and $2 == id.name
            end
            # One identity is guaranteed to match because the input has been schema validated.
            if unions.empty?
                return sid
            else
                return CBOR::Tagged.new(45, sid) # See RFC 9254 section 9.3.
            end

        when 'string', 'boolean'
            value

        when 'instance-identifier'
            raise "Missing schema!" if schema.nil?
            val, _ = iid2cbor(schema, value)
            val

        end
    rescue => e
        STDERR.puts "Error encoding #{value or "nil"} as type #{type ? type.name : "nil"}: #{e.message}"
        return value
    end
end

# Split an element into arg and keys
# E.g. element: "vlan-registration-entry[database-id='0'][vids='1']"
# arg: = "vlan-registration-entry"
# keys: [["database-id", "0"], ["vids", "1"]]
# See RFC 7951 section 6.11.
def iid_element_split(element)
    raise "Mismatching square brackets in #{element}" if element.count("]") != element.count("[")
    ss = element.gsub "]", ""
    a = ss.split("[")
    arg = a.shift
    keys = []
    a.each do |x|
        if x =~ /([\w-]+)\s*=\s*(.*)/
            n = $1
            v = $2
            if v =~ /'(.*)'/ or v =~ /"(.*)"/
                keys << [n, $1]
            else
                keys << [n, v]
            end
        else
            raise "Invalid key syntax: #{s}"
        end
    end
    return arg, keys
end

# All of the key values are strings but a few needs to be converted to other types.
def convert_iid_key_value(type, key, value)
    case type.name
    when 'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32'
        Integer(value) # Convert String to Integer
    when 'boolean'
        raise "Invalid value in key #{key}" if !['true', 'false'].include?(value)
        value == 'true' # Convert String to True or False
    when 'empty'
        raise "Invalid value in key #{key}" if value != '[null]'
        nil # Convert String to nil
    else
        value # Keep as String
    end
end

# Function to split an iid on '/' but not if inside square brackets
# Using String.split('/') does not work if a key contains a '/',
# such as in "route[destination-prefix='10.10.1.0/28']"
def split_iid_outside_brackets(iid)
  result = []
  buffer = ""
  inside_brackets = false

  iid.each_char do |char|
    if char == '['
      inside_brackets = true
    elsif char == ']'
      inside_brackets = false
    elsif char == '/' && !inside_brackets
      result << buffer unless buffer.empty?
      buffer = ""
      next
    end
    buffer << char
  end

  result << buffer unless buffer.empty?
  result
end

# Convert a YANG instance-identifier in JSON format to CBOR
# See RFC 7951 section 6.11.
def iid2cbor(schema, iid)
    s = schema
    found = []
    all_keys = []
    split_iid_outside_brackets(iid).each do |e|
        element_name, keys = iid_element_split(e)
        c = s.substms.find{|x| x.arg == element_name}
        raise "Could not find /#{(found + [e]).join("/")} in schema tree" if c.nil?
        found << e
        s = c

        keys.each do |k|
            ck = s.substms.find{|x| x.arg == k[0]}
            raise "Could not find key: #{k[0]} /#{(found + [e]).join("/")} in schema tree" if ck.nil?
            all_keys << type2cbor(ck.type, convert_iid_key_value(ck.type, k[0], k[1]))
        end
    end
    val = s.sid
    val = all_keys.unshift s.sid if all_keys.size > 0
    return val, s
end

# Validate JSON data against schema
def json_validate(schema, json, content_format, continue_on_error)
    json_schema = to_json_schema(schema, content_format)
    schemer = JSONSchemer.schema(json_schema)
    errors = false
    schemer.validate(json).each do |error|
        errors = true
        STDERR.puts JSONSchemer::Errors.pretty(error)
    end
    if errors
        if continue_on_error
            puts "Errors in JSON data"
        else
            raise "Errors in JSON data"
        end
    end
end

# Convert a YANG instance in JSON format to CBOR
# Validation of a null value is skipped in all other than 'post' content formats,
# as a null value is always valid in content formats like 'fetch' and 'ipatch'.
def instance2cbor(schema, json, content_format, continue_on_error)
    raise "YANG instance must be a single JSON map!" if !json.is_a? Hash or json.length != 1
    key = json.keys[0]
    value = json.values[0]
    key_part, iid_schema = iid2cbor(schema, key)
    val_part = nil
    if !value.nil? or content_format == 'post'
        json_validate(iid_schema, value, content_format, continue_on_error)
        val_part = json2cbor(iid_schema, value, content_format)
    end
    return {key_part => val_part}
end

# Parse the different JSON content formats and convert to binary CBOR data
def json_seq2cbor(schema, json, content_format, continue_on_error = false)
    buf = "".b
    case content_format
    when 'fetch'
        raise "Input is not an Array!" if !json.is_a? Array
        json.each do |j|
            if j.is_a? Hash
                buf << CBOR.encode(instance2cbor(schema, j, content_format, continue_on_error))
            else
                val, _ = iid2cbor(schema, j)
                buf << CBOR.encode(val)
            end
        end
    when 'ipatch'
        raise "Input is not an Array!" if !json.is_a? Array
        json.each { |j| buf << CBOR.encode(instance2cbor(schema, j, content_format, continue_on_error)) }
    when 'post'
        raise "Input is not an Array!" if !json.is_a? Array
        json.each { |j| buf << CBOR.encode(instance2cbor(schema, j, content_format, continue_on_error)) }
    when 'yang', 'get', 'put'
        raise "Input is not a Hash!" if !json.is_a? Hash
        json_validate(schema, json, content_format, continue_on_error)
        buf << CBOR.encode(json2cbor(schema, json, content_format))
    else
        raise "Invalid content_format #{content_format}!"
    end
    return buf
end

# Return true iff 'value' can possibly be a JSON encoding of YANG type 'type'.
# See RFC 7951 section 6.10.
def match_type_json(type, value)
    return match_type_json(type.deref.type, value) if type.name == 'leafref'

    case value

    when Integer
        return (['int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32'].include?(type.name) and
                type.ranges.any? {|r| r.include? value})

    when [nil]
        return type.name == 'empty'

    when true, false
        return type.name == 'boolean'

    when String
        begin
            x = Integer(value)
            if ['int64', 'decimal64', 'uint64'].include?(type.name)
                return type.ranges.any? {|r| r.include? x}
            end
        rescue ArgumentError
            begin
                x = BigDecimal(value)
                if type.name == 'decimal64'
                    return type.ranges.any? {|r| r.include? x}
                end
            rescue ArgumentError
            end
        end

        if type.name == 'string'
            return (type.patterns.all? {|p| p.match? value} and
                    type.length.any? {|l| l.include? value.length})
        elsif type.name == 'binary'
            return type.length.any? {|l| l.include? value.length}
        elsif type.name == 'bits'
            return value.split(' ').all? {|name| type.bits[name] != nil}
        elsif type.name == 'enumeration'
            return type.enums[value] != nil
        elsif type.name == 'identityref'
            type.deref.map(&:derived_from).reduce(:&).each do |id|
               return true if id.name == value
               return true if value =~ /(.+):(.+)/ and $1 == id.mod and $2 == id.name
            end
            return false
        else
            return type.name == 'instance-identifier'
        end
    end

    return false
end

# Find the node identified by SID
# Returns:
# The node found or nil
# The path to the node as an array of nodes up to and including the requested node
def find_node_from_sid(node, sid, path = [])
    return node, path if node.sid == sid
    node.substms.each do |n|
        path.push(n)
        child, _ = find_node_from_sid(n, sid, path)
        return child, path if child
        path.pop
    end
    return nil, path
end

# Split CBOR IID into SID and keys[]
# Note that '<SID>' and '[ <SID> ]' is treated in the same way
def split_iid(iid)
    iid = iid.clone # Do not modify the original
    sid = 0
    keys = []
    case iid
    when Integer
        sid = iid
    when Array
        sid = iid.shift
        abort("Invalid SID class in IID (#{sid.class})!") if sid.class != Integer
        keys = iid
    else
        abort("Invalid SID class in IID (#{iid.class})!")
    end
    return sid, keys
end

def cbor2json_hash(node, cbor, content_format)
    result = {}
    cbor.each do |sid, value|
        if !sid.is_a? Integer
            STDERR.puts "In #{node.kw} #{node.arg}: expected SID but found #{sid.class}, skipping..."
            next
        end
        absolute_sid = sid + node.sid
        child = node.substms.find { |c| c.sid == absolute_sid }
        if child.nil?
            STDERR.puts "Can't find SID #{absolute_sid} in #{node.kw} #{node.arg}, skipping..."
            next
        end
        result[child.arg] = cbor2json(child, value, content_format)
    end
    result
end

def cbor2json_array(node, cbor, content_format)
    return cbor.map do |entry|
        result = {}
        entry.each do |sid, value|
            if !sid.is_a? Integer
                STDERR.puts "In #{node.kw} #{node.arg}: expected SID but found #{sid.class}, skipping..."
                next
            end
            absolute_sid = sid + node.sid
            child = node.substms.find { |c| c.sid == absolute_sid }
            if child.nil?
                STDERR.puts "Can't find SID #{absolute_sid} in #{node.kw} #{node.arg}, skipping..."
                next
            end
            result[child.arg] = cbor2json(child, value, content_format)
        end
        result
    end
end

def cbor2json(node, cbor, content_format)
    node.sid = 0 if node.kw == 'module'
    case node.kw
    when 'module', 'container', 'input', 'output'
        result = {}
        if cbor.is_a? Hash
            result = cbor2json_hash(node, cbor, content_format)
        else
            STDERR.puts "In #{node.kw} #{node.arg}: expected Hash but found #{cbor.class}"
        end
        result

    when 'list'
        result = []
        if ['fetch', 'ipatch'].include?(content_format)
            if cbor.is_a? Array
                result = cbor2json_array(node, cbor, content_format)
            elsif cbor.is_a? Hash
                result = cbor2json_hash(node, cbor, content_format)
            else
                STDERR.puts "In #{node.kw} #{node.arg}: expected Array or Hash but found #{cbor.class}"
            end
        else
            if cbor.is_a? Array
                result = cbor2json_array(node, cbor, content_format)
            else
                STDERR.puts "In #{node.kw} #{node.arg}: expected Array but found #{cbor.class}"
            end
        end
        result

    when 'leaf'
        return type2json(node.type, cbor)

    when 'leaf-list'
        return cbor.map {|entry| type2json(node.type, entry)}

    when 'anydata'
        if node.arg == 'board:factory_default_config'
            ds_schema = yang_schema_get
            return cbor2json(ds_schema, cbor, content_format)
        end

    when 'rpc', 'action'
        if cbor.nil? or (cbor.is_a? Hash and cbor.empty?)
            def mandatory?(node)
                return node if node.mandatory
                node.substms.each do |s|
                    m = mandatory?(s)
                    return m if m
                end
                return nil
            end
            mandatory = mandatory?(node)
            raise "#{node.kw} #{node.arg}: Mandatory '#{mandatory.kw} #{mandatory.arg}' not found!" if mandatory
            return cbor.nil? ? nil : {} # This is ok if there are no mandatory parameters
        end

        raise "In #{node.kw} #{node.arg}: expected non-empty Hash but found #{PP.pp(cbor, '')}" if !cbor.is_a? Hash or cbor.empty?

        result = {}

        # Let first SID (first hash key) in CBOR data determine if data belongs to 'input' or 'output'
        sid = cbor.keys[0]
        absolute_sid = sid + node.sid
        parent = nil
        node.substms.each do |child|
            case child.kw
            when 'input'
                if child.substms.find { |c| c.sid == absolute_sid }
                    parent = child # First SID found in 'input' node
                    break
                end
            when 'output'
                if child.substms.find { |c| c.sid == absolute_sid }
                    parent = child # First SID found in 'output' node
                    break
                end
            else
                raise "Invalid child node #{child.kw} in 'rpc'/'action'!"
            end
        end
        raise "'input'/'output' node not found" if parent.nil?
        # Child SIDs of 'input'/'output' must be relative to the SID in 'rpc'/'action'.
        # See core-comi-19 section 3.5.
        # TODO jea: Replace with RFC xxxx above when ready
        saved_sid = parent.sid # Save parent.sid for later restore
        parent.sid = node.sid
        result[parent.kw] = cbor2json(parent, cbor, content_format)
        parent.sid = saved_sid # Restore parent.sid
        result

    else
        abort("Invalid keyword #{node.kw}")
    end
end

# Convert CBOR data to JSON
# Validation of a null value is skipped in all other than 'post' content formats,
# as a null value is always valid in content formats like 'fetch' and 'ipatch'.
def instance2json(schema, cbor, content_format)
    result = {}
    if !cbor.is_a? Hash or cbor.length != 1
        STDERR.puts "YANG instance must be a single CBOR map!"
        return result
    end
    key = cbor.keys[0]
    sid, _ = split_iid(key)
    node, _ = find_node_from_sid(schema, sid)
    value = cbor.values[0]
    json_key = iid2json(schema, key)
    if !value.nil? or content_format == 'post'
        result[json_key] = cbor2json(node, value, content_format)
    else
        result[json_key] = nil
    end
    return result
end

# Convert CBOR sequence to JSON depending on the content format
# Note that CBOR is always an array even if there is only one CBOR item
def cbor_seq2json(schema, cbor, content_format)
    result = []
    case content_format
    when 'fetch'
        cbor.each do |c|
            if c.is_a? Hash
                result << instance2json(schema, c, content_format) # FETCH response
            else
                result << iid2json(schema, c) # FETCH request
            end
        end
        return result
    when 'ipatch'
        cbor.each { |c| result << instance2json(schema, c, content_format) } # iPATCH request
        return result
    when 'post'
        cbor.each { |c| result << instance2json(schema, c, content_format) } # POST request
        return result
    when 'yang', 'get', 'put'
        if cbor.length != 1
            STDERR.puts "content format 'yang' does not support CBOR sequences!"
            return result
        end
        cbor.each { |c| result << cbor2json(schema, c, content_format) }
        return result[0]
    else
        STDERR.puts "Invalid content_format #{content_format}!"
        return result
    end
end

def type2json(type, value, schema = nil)
    begin
        case type.name

        when 'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32'
            value

        when 'int64', 'uint64'
            value.to_s # See RFC 7951 section 6.1.

        when 'empty'
            [value] # See RFC 7951 section 6.9.

        when 'string', 'boolean'
            value

        when 'binary'
            Base64.strict_encode64 value # See RFC 7951 section 6.6.

        when 'enumeration'
            return value.value if value.is_a? CBOR::Tagged
            _, enum = type.enums.find {|_, enum| enum.value == value}
            enum.name

        when 'bits'
            return value.value if value.is_a? CBOR::Tagged

            offset = 0
            positions = []

            value = [value] if value.is_a? String
            value.each do |v|
                if v.is_a? Integer
                    offset += 8 * v
                else
                    v.each_byte do |byte|
                        8.times {|i| positions << offset + i if byte[i] != 0}
                        offset += 8
                    end
                end
            end

            positions.map {|p| type.bits.values.find {|b| b.position == p}.name}.join(' ')

        when 'leafref'
            type2json(type.deref.type, value)

        when 'identityref'
            sid = value
            sid = value.value if value.is_a? CBOR::Tagged
            id = type.deref.map(&:derived_from).reduce(:&).find {|id| id.sid == sid}
            "#{id.mod}:#{id.name}"

        when 'union'
            t = type.members.find {|t| match_type_cbor(t, value)}
            type2json(t, value)

        when 'decimal64'
            decode_decimal64(value)

        when 'instance-identifier'
            iid2json(schema ? schema : yang_schema_get, value)

        end
    rescue => e
        STDERR.puts "Error decoding #{value or "nil"} as type #{type ? type.name : "nil"}: #{e.message}"
        return value
    end
end

# Return true iff 'value' can possibly be a CBOR encoding of YANG type 'type'.
def match_type_cbor(type, value)
    return match_type_cbor(type.deref.type, value) if type.name == 'leafref'

    case value

    when CBOR::Tagged
        begin
            if value.tag == 4 and type.name == 'decimal64'
                x = BigDecimal(decode_decimal64(value))
                return type.ranges.any? {|r| r.include? x}
            elsif value.tag == 44 and type.name == 'enumeration'
                return type.enums[value.value] != nil
            elsif value.tag == 43 and type.name == 'bits'
                return value.value.split(' ').all? {|name| type.bits[name] != nil}
            elsif value.tag == 45 and type.name == 'identityref'
                return (type.deref.map(&:derived_from).reduce(:&).find {|id| id.sid == value.value} != nil)
            end
        rescue => e
            return false
        end

    when nil
        return type.name == 'empty'

    when true, false
        return type.name == 'boolean'

    when Integer
        return (['int8', 'int16', 'int32', 'int64', 'uint8', 'uint16', 'uint32', 'uint64'].include?(type.name) and
                type.ranges.any? {|r| r.include? value})

    when String
        if type.name == 'binary'
            return (value.encoding == Encoding::ASCII_8BIT and
                    type.length.any? {|l| l.include? value.length})
        elsif type.name == 'string'
            return (type.patterns.all? {|p| p.match? value} and
                    type.length.any? {|l| l.include? value.length})
        end
    end

    return false
end

def decode_decimal64(value)
    exponent, mantissa = value.value
    (mantissa * (10 ** exponent)).to_f.to_s
end

# Convert IID to a JSON string. See RFC 7951 section 6.11
def iid2json(schema, value)
    iid_str = ""
    sid, keys = split_iid(value)
    _, path = find_node_from_sid(schema, sid)
    path.each do |node|
        if node.kw == 'list'
            keys_str = ""
            node.substms.each do |s|
                if node.keys && node.keys.include?(s.arg)
                    key = keys.shift
                    keys_str += "[#{s.arg}='#{type2json(s.type, key)}']" if key
                end
            end
            iid_str += "/#{node.arg}#{keys_str}"
        else
            iid_str += "/#{node.arg}"
        end
    end
    iid_str
end

def to_json_schema(stm, content_format)
    properties = {}
    required = []
    stm.substms.each do |s|
        if ['ipatch', 'put'].include?(content_format) and s.config == false
            next # Skip status nodes in JSON schema
        end
        properties[s.arg] = to_json_schema(s, content_format) if Yang::DATA_NODES.include? s.kw
        properties[s.kw] = to_json_schema(s, content_format) if s.kw == 'input' or s.kw == 'output'
        required << s.arg if s.mandatory
    end

    case stm.kw

    when 'module'
        schema = {
            :title => stm.arg,
            :'$schema' => 'http://json-schema.org/draft-07/schema#',
            :type => 'object',
            :additionalProperties => false,
            :properties => properties,
        }
        schema[:required] = required if !required.empty?

    when 'container'
        schema = {
            :type => 'object',
            :additionalProperties => false,
            :properties => properties,
        }
        schema[:required] = required if !required.empty?

    when 'leaf'
        schema = type2schema(stm.type)

    when 'leaf-list'
        schema = {
            :type => 'array',
            :items => type2schema(stm.type)
        }
        schema['uniqueItems'] = true if stm.config # See RFC 7950 section 7.7.

    when 'list'
        schema = {
            :type => 'array',
            :items => {
                :type => 'object',
                :additionalProperties => false,
                :required => ((stm.keys or []) + required).uniq,
                :properties => properties
            }
        }
        if ['fetch', 'ipatch'].include?(content_format)
            # Accept either array or object in FETCH and iPATCH
            schema = {
                'oneOf': [ schema,
                           {
                               :type => 'object',
                               :additionalProperties => false,
                               :required => ((stm.keys or []) + required).uniq,
                               :properties => properties,
                           }
                         ]
            }
        end

    when 'anydata'
        if stm.arg == 'board:factory_default_config'
            ds_schema = yang_schema_get
            schema = to_json_schema(ds_schema, 'put')
        else
            schema = {}
        end

    when 'anyxml'
        schema = {}

    when 'input', 'output'
        if stm.substms.empty?
            schema = {
                :type => 'null',
            }
        else
            schema = {
                :type => 'object',
                :additionalProperties => false,
                :properties => properties,
            }
            required = []
            stm.substms.each { |s| required << s.arg if s.mandatory }
            schema[:required] = required if !required.empty?
        end

    when 'action', 'rpc'
        input_node = stm.substms.find { |s| s.kw == 'input' }
        raise "Missing input statement in #{stm.kw} #{stm.arg}" if input_node.nil?
        output_node = stm.substms.find { |s| s.kw == 'output' }
        raise "Missing output statement in #{stm.kw} #{stm.arg}" if output_node.nil?

        if input_node.substms.empty? and output_node.substms.empty?
            schema = {
                :type => 'null',
            }
        else
            schema = {
                'oneOf': [
                               {
                                   :type => 'null',
                               },
                               {
                                   :type => 'object',
                                   :additionalProperties => false,
                                   :properties => properties,
                               }
                           ]
            }
        end

    end

    schema['description'] = stm.description if stm.description
    return schema
end

def type2schema(type)
    case type.name

    when 'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32'
        {
            :type => 'integer',
            :anyOf => type.ranges.map {|r|
                {
                    :minimum => r.min,
                    :maximum => r.max
                }
            }
        }

    when 'int64', 'uint64' # See RFC 7951 section 6.1.
        { :type => 'string' }

    when 'decimal64' # See RFC 7951 section 6.1.
        {
            :type => 'string',
            :pattern => "^(\\+|-)?\\d*(\\.\\d{0,#{type.fraction_digits}})?$"
        }

    when 'boolean'
        { :type => 'boolean' }

    when 'union'
        { :anyOf => type.members.map {|t| type2schema(t)} }

    when 'enumeration'
        { :enum => type.enums.keys }

    when 'empty'
        # See RFC 7951 section 6.9.
        {
            :type => 'array',
            :items => { :type => 'null' },
            :minItems => 1,
            :maxItems => 1
        }

    when 'binary'
        # See RFC 7951 section 6.6.
        {
            :type => 'string',
            :contentEncoding => 'base64',
            :anyOf => type.length.map {|l|
                {
                    :minLength => l.min,
                    :maxLength => l.max
                }
            }
        }

    when 'bits'
        # See RFC 7951 section 6.5.
        words = "(#{type.bits.keys.join('|')})"
        {
            :type => 'string',
            :pattern => "^#{words}?(\\s#{words})*$"
        }

    when 'leafref'
        type2schema(type.deref.type)

    when 'identityref'
        # The permissible identity names is the intersection of identites derived from the base identities.
        # See RFC 7950 section 9.10.2.
        enums = []
        type.deref.map(&:derived_from).reduce(:&).each do |id|
            enums << "#{id.mod}:#{id.name}"
            enums << id.name if id.mod == type.mod
        end
        { :enum => enums }

    when 'string'
        schema = {
            :type => 'string',
            :anyOf => type.length.map {|l|
                {
                    :minLength => l.min,
                    :maxLength => l.max
                }
            }
        }

        if !type.patterns.empty?
            schema['allOf'] = type.patterns.map {|p|
                {
                    :pattern => p.source
                }
            }
        end

        schema

    else
        { :type => 'string' }

    end
end

main if $0 == __FILE__
