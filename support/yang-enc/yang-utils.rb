# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'nokogiri'
require 'json'
require 'bigdecimal'
require 'tsort'

module Yang

class ModuleSet
    attr_reader :modules
    include TSort

    def initialize
        @modules = {}
    end

    def add_module(yin)
        xml = Nokogiri::XML(yin) do |config|
            config.strict.noblanks
        end

        xml.css('> module').each do |m|
            @modules[m['name']] = Module.new(m)
        end

        return self
    end

    def ast_clear
      @modules.each do |k, v|
        v.ast = nil
      end
    end

    def add_sid_file(path)
        sid_file = JSON.parse(File.read(path))
        src_mod = find_module(sid_file['module-name'])

        sid_file['items'].each do |item|
            if item['namespace'] == 'module'
                m = find_module(item['identifier'])
                m.schema.sid = item['sid'] if m
            elsif item['namespace'] == 'data'
                schema_path = item['identifier'][1..].split('/')
                dst_mod = find_module(schema_path[0].split(':').first)
                target = dst_mod.schema.resolve_schema_path(schema_path)
                target.sid = item['sid'] if target
            elsif item['namespace'] == 'identity'
                id = src_mod.identity.find {|id| id.name == item['identifier']}
                id.sid = item['sid'] if id
            end
        end

        return self
    end

    def find_module(name)
        @modules[name]
    end

    def tsort_each_node &block
      @modules.each_value(&block)
    end

    def tsort_each_child node, &block
      @modules.each_value.select{|c| node.imports? c}.each(&block)
    end

    def schema
        # Topologically sort module dependency graph.
        # This ensures that we have processed module A before any modules that augment into A.
        # There are no cycles in the dependency graph. See RFC 7950 section 5.1.
        sorted = self.tsort
        sorted.each {|mod| mod.interpret(self)}
        sorted.each do |mod| # TODO: rewrite interpret into a pure function that threads a context to handle deviations and augments
            mod.ast.css('> deviation').each do |deviation|
                mod.interpret_deviation(deviation, self)
            end
        end
        sorted.each {|mod| mod.resolve_leafref(mod.schema)}
        return self
    end

    def data
        def flatten(stm)
            stmt = stm.dup

            stm.substms.each do |s|
                if ['choice', 'case'].include? s.kw
                    flatten(s).substms.each {|s| stmt.add_child(s)}
                else
                    stmt.add_child(flatten(s))
                end
            end

            return stmt
        end

        root = Statement.new('module', 'data-tree-schema')

        @modules.each do |_, mod|
            mod.schema.substms.each do |top_lvl_stm|
                root.add_child(flatten(top_lvl_stm))
            end
        end

        return root
    end
end

class Module
    attr_accessor :ast
    attr_reader :schema, :identity

    def initialize(ast)
        @ast = ast
        @imports = {}
        @ast.css('> import').each do |import|
            import.css('> prefix').each do |p|
                @imports[p['value']] = import['module']
            end
        end
        @identity = []
    end

    def imports?(other)
        @imports.values.include? other.name
    end

    def name
        @ast['name']
    end

    def interpret(modules)
        @schema = interpret_stm(@ast, modules)
    end

    def resolve_prefix(prefix, modules)
        if self.prefix == prefix
            self
        else
            modules.find_module(@imports[prefix])
        end
    end

    def prefix
        @ast.css('> prefix').each do |p|
            return p['value']
        end

        return nil
    end

    def interpret_stm(stm, modules, groupings = [])
        if stm.parent.name == 'module'
            stmt = Statement.new(stm.name, "#{self.name}:#{stm['name']}")
        else
            stmt = Statement.new(stm.name, stm['name'])
        end

        groupings << stmt if stm.name == 'grouping'

        stmt.description = get_description(stm)

        stm.css('> config').each do |config|
            stmt.config = config['value'] == 'true'
        end

        stm.css('> default').each do |default|
            stmt.default = default['value']
            #TODO: default should come from type if no default specified?
        end

        stm.css('> type').each do |type|
            stmt.type = interpret_type(type, modules)
        end

        stm.css('> mandatory').each do |mandatory|
            stmt.mandatory = mandatory['value'] == 'true'
        end

        status = stm.at_css('> status')
        stmt.status = status['value'] if status

        if ['rpc', 'action'].include? stm.name
            # See RFC 7950 section 7.14. and 7.15.
            stmt.add_child(Statement.new('input')) if stm.at_css('> input').nil?
            stmt.add_child(Statement.new('output')) if stm.at_css('> output').nil?
        end

        stm.children.each do |c|
            if e = resolve_extension(c, modules)
                next if interpret_extension(e, c, modules, stmt)
            end

            if stm.name == 'choice' and IMPLICIT_CASE_NODES.include? c.name
                # See RFC 7950 section 7.9.2.
                implicit_case = stmt.add_child(Statement.new('case', c['name']))
                child = implicit_case.add_child(interpret_stm(c, modules, groupings))
                # Implicit case statements should have the same "status" as the data node it represents.
                implicit_case.status = child.status
            elsif SCHEMA_NODES.include? c.name
                stmt.add_child(interpret_stm(c, modules, groupings))
            elsif c.name == 'uses'
                grouping, src_mod = resolve_grouping(c['name'], c, modules)
                grouping = src_mod.interpret_stm(grouping, modules, groupings)

                # The identifiers defined in the grouping are bound to the namespace of the current module.
                # See RFC 7950 section 7.13.
                grouping.substms.each {|c| stmt.add_child(c)}

                c.css('> augment').each do |augment|
                    groupings << grouping
                    interpret_augment(augment, modules, groupings)
                end

                resolve_leafref(grouping, true) if groupings.empty?
            end
        end

        stm.css('> augment').each {|augment| interpret_augment(augment, modules, groupings)}

        stm.css('> identity').each {|id| interpret_identity(id, modules)}

        # Make sure order of keys is the same as order of 'key' statement.
        stm.css('> key').each do |key|
            stmt.keys = key['value'].split(' ')
            stmt.keys.each do |k1|
                stmt.keys.each do |k2|
                    i = stmt.substms.index {|s| s.arg == k1}
                    j = stmt.substms.index {|s| s.arg == k2}
                    stmt.substms[i], stmt.substms[j] = stmt.substms[j], stmt.substms[i] if i < j
                end
            end
        end

        groupings.pop if stm.name == 'grouping'
        return stmt
    end

    def interpret_extension(extension, stm, modules, stmt)
        def add_extension_tag(stmt, extension)
            stmt.add_tag(:extension, extension)
            stmt.substms.each { |s| add_extension_tag(s, extension) }
        end

        extension_stms = interpret_stm(stm, modules) # Add all substatements recursively
        add_extension_tag(extension_stms, extension) # Add extension tag to all statements inside extension

        mod, ext = extension.split(':')
        case ext
        when 'yang-data'
            # This extension is ignored unless it appears as a top-level statement.
            # See RFC 8040 section 8.
            return nil if stmt.kw != 'module'

            # It MUST contain data definition statements that result in exactly one container data node definition.
            # See RFC 8040 section 8.
            raise "Number of data nodes in 'yang-data' is not one" if extension_stms.substms.length != 1
            container_stmt = extension_stms.substms[0]
            raise "Container not found in 'yang-data'" if container_stmt.kw != 'container'

            container_stmt.arg.prepend(self.name, ':') # Container will become a root node. Prepend with '<module name>:'
            stmt.add_child(container_stmt) # Add container and its children
            stmt
        else
            nil
        end
    end

    def interpret_augment(augment, modules, groupings)
        dst_mod, schema_path = schema_node_id2schema_path(augment['target-node'], modules)

        if !groupings.empty?
            target = groupings.pop.resolve_schema_path(schema_path)
        else
            target = dst_mod.schema.resolve_schema_path(schema_path)
        end

        # TODO: throw an exception?
        puts "Augment: #{augment['target-node']} not found! #{schema_path}" if target.nil?

        interpret_stm(augment, modules, groupings).substms.each do |c|
            if dst_mod == self
                target.add_child(c)
            elsif target.arg =~ /(.+):.+/ and $1 == self.name
                target.add_child(c)
            else
                # The augmented nodes are in the namespace of the augmenting module.
                # See RFC 7950 section 4.2.8.
                target.add_child(c.rename("#{self.name}:#{c.arg}"))
            end
        end
    end

    def interpret_deviation(deviation, modules)
        dst_mod, schema_path = schema_node_id2schema_path(deviation['target-node'], modules)
        target = dst_mod.schema.resolve_schema_path(schema_path)

        puts "Deviation: #{deviation['target-node']} not found! #{schema_path}" if target.nil?

        deviation.css('> deviate').each do |deviate|
            case deviate['value']
            when 'not-supported'
                target.remove
            when 'replace'
                deviate.css('> config').each do |config|
                    target.config = config['value'] == true
                end

                deviate.css('> type').each do |type|
                    target.type = interpret_type(type, modules)
                end
            when 'add', 'delete'
                # TODO: throw an exception?
                abort("UNIMPLEMENTED:L#{__LINE__}: deviate #{deviate['value']} is not implemented!")
            end
        end
    end

    def interpret_type(type, modules)
        if BUILTIN_TYPES.include? type['name']
            if ['enumeration', 'bits'].include? type['name']
                t = Universe.new(type['name'])
            else
                t = Type.new(type['name'])
            end
        else
            typedef, src_mod = resolve_typedef(type['name'], type, modules)
            base = typedef.at_css('> type') # Guaranteed to be present. See RFC 7950 section 7.3.1.
            t = src_mod.interpret_type(base, modules)
            t.description = get_description(typedef)
        end

        bits = type.css('> bit').map do |b|
            position = b.at_css('> position')
            position = position['value'].to_i if position
            Bit.new(b['name'], position, get_description(b))
        end
        t = t.restrict_bits(bits) if !bits.empty?

        enums = type.css('> enum').map do |e|
            value = e.at_css('> value')
            value = value['value'].to_i if value
            Enum.new(e['name'], value, get_description(e))
        end
        t = t.restrict_enums(enums) if !enums.empty?

        type.css('> type').each do |typ|
            t.add_member(interpret_type(typ, modules))
        end

        type.css('> fraction-digits').each do |digits|
            t.set_fraction_digits(digits['value'].to_i)
        end

        type.css('> path').each do |path|
            t.path = schema_node_id2schema_path(path['value'].gsub(/\[.*\]/, ''), modules)
        end

        type.css('> base').each do |base|
            t.mod = self.name
            base, src_mod = resolve_identity(base['name'], modules)
            t.deref = [] if t.deref.nil?
            t.deref << src_mod.interpret_identity(base, modules)
        end

        type.css('> pattern').each do |pattern|
            t.add_pattern(pattern['value'])
        end

        type.css('> range').each do |range|
            t.add_range(range['value'])
        end

        type.css('> length').each do |length|
            t.add_length(length['value'])
        end

        return t
    end

    def interpret_identity(stm, modules)
        this = @identity.find {|id| id.name == stm['name']}
        return this if this

        this = Identity.new(stm['name'], self.name)

        stm.css('> base').each do |base|
            id, mod = resolve_identity(base['name'], modules)
            base = mod.interpret_identity(id, modules)
            this.base << base
            base.derived << this
        end

        @identity << this
        return this
    end

    def resolve_leafref(stm, relative = false)
        if stm.type and stm.type.name == 'leafref'
            return if stm.type.deref

            mod, schema_path = stm.type.path

            if schema_path[0] == '..'
                stm.type.deref = stm.resolve_schema_path(schema_path)
                stm.type.path = schema_path
            elsif not relative
                stm.type.deref = mod.schema.resolve_schema_path(schema_path)
                stm.type.path = schema_path
            end
        else
            stm.substms.each {|s| resolve_leafref(s, relative)}
        end
    end

    private

    def schema_node_id2schema_path(schema_node_id, modules)
        dst_mod = nil

        if schema_node_id[0] == '/'
            parent_mod = nil
            path =
                schema_node_id[1..]
                .split('/')
                .map do |id|
                    mod, id = resolve_name(id, modules)
                    dst_mod = mod if dst_mod.nil?

                    if mod == parent_mod
                        id
                    else
                        parent_mod = mod
                        "#{mod.name}:#{id}"
                    end
                end
        else
            dst_mod = self
            path = schema_node_id.split('/').map {|id| id.gsub(/.+:/, '')}
        end

        return dst_mod, path
    end

    def resolve_extension(stm, modules)
        # Prefix is always required when an extension is used.
        # See RFC 7950 section 6.3.1 and 7.19
        prefix = stm&.namespace&.prefix
        return nil if prefix.nil?
        mod = modules.find_module(@imports[prefix]) # Find module were extension is defined
        return nil if mod.nil?
        ext = mod.ast.at_css("extension[name='#{stm.name}']") # Verify that the extension is defined
        return "#{mod.name}:#{ext['name']}" if ext
        nil
    end

    def resolve_grouping(name, stm, modules)
        mod, id = resolve_name(name, modules)

        if mod == self
            stm.ancestors.each do |ancestor|
                ancestor.css("> grouping[name=#{id}]").each do |defn|
                    return defn, mod
                end
            end
        elsif mod
            return mod.ast.at_css("> grouping[name=#{id}]"), mod
        end
    end

    def resolve_typedef(name, stm, modules)
        mod, id = resolve_name(name, modules)

        # TODO: factor this logic into a function that resolve_typedef and resolve_grouping can use
        if mod == self
            stm.ancestors.each do |ancestor|
                ancestor.css("> typedef[name=\"#{id}\"]").each do |defn|
                    return defn, mod
                end
            end
        elsif mod
            return mod.ast.at_css("> typedef[name=\"#{id}\"]"), mod
        end
    end

    def resolve_identity(name, modules)
        mod, id = resolve_name(name, modules)
        return mod.ast.at_css("> identity[name=\"#{id}\"]"), mod
    end

    def resolve_name(name, modules)
        prefix, id = name.split(':')

        if id
            return resolve_prefix(prefix, modules), id
        elsif prefix
            return self, prefix
        else
            return nil, nil
        end
    end

    def get_description(stm)
        stm.css('> description > text').each do |d|
            return d.text
        end

        return nil
    end
end

class Statement
    attr_reader   :kw, :substms, :tags
    attr_accessor :arg, :description, :config, :default, :type, :keys, :parent, :sid, :mandatory, :status

    def initialize(keyword, arg = nil)
        @kw = keyword
        @arg = arg
        @substms = []
        @config = true
        @status = "current"
        @tags = {}
    end

    def initialize_copy(other)
        super
        @substms = []
        @keys = other.keys.dup if other.keys
        @type = other.type.dup if other.type
    end

    def add_child(c)
        s = @substms.find {|s| s.kw == c.kw and s.arg == c.arg}
        return s if s
        @substms << c
        propagate_config_false if not @config
        c.parent = self
        return c
    end

    def remove
        if @parent
            @parent.substms.delete(self)
            @parent = nil
        end

        return self
    end

    def rename(new_name)
        @arg = new_name
        return self
    end

    def resolve_schema_path(schema_path)
        return self if schema_path.empty?
        return @parent.resolve_schema_path(schema_path[1..]) if schema_path[0] == '..' and @parent

        @substms.each do |s|
            return s.resolve_schema_path(schema_path[1..]) if s.arg == schema_path[0]
        end

        if ['action', 'rpc'].include? @kw and ['input', 'output'].include? schema_path[0]
            s = @substms.find {|s| s.kw == schema_path[0]}
            return s.resolve_schema_path(schema_path[1..]) if s
        end

        return nil
    end

    def add_tag(key, value)
        @tags[key] = value
    end

    protected

    def propagate_config_false
        @config = false

        @substms.each do |s|
            s.propagate_config_false if s.config
        end
    end
end

class Type
    attr_reader   :fraction_digits, :name
    attr_accessor :description, :bits, :enums, :members, :path, :deref, :mod, :ranges

    def initialize(name)
        @name = name
        @ranges = [Range.new(-128, 127)]                                 if @name == 'int8'
        @ranges = [Range.new(-32768, 32767)]                             if @name == 'int16'
        @ranges = [Range.new(-2147483648, 2147483647)]                   if @name == 'int32'
        @ranges = [Range.new(-9223372036854775808, 9223372036854775807)] if @name == 'int64'
        @ranges = [Range.new(0, 255)]                                    if @name == 'uint8'
        @ranges = [Range.new(0, 65535)]                                  if @name == 'uint16'
        @ranges = [Range.new(0, 4294967295)]                             if @name == 'uint32'
        @ranges = [Range.new(0, 18446744073709551615)] if ['uint64', 'binary', 'string'].include? @name
    end

    def initialize_copy(other)
        super
        @bits = other.bits.map {|k, v| [k, v.dup]}.to_h if other.bits
        @enums = other.enums.map {|k, v| [k, v.dup]}.to_h if other.enums
        @members = other.members.map {|v| v.dup} if other.members
    end

    def add_member(type)
        @members = [] if @members.nil?
        @members << type
        return self
    end

    def add_pattern(pattern)
        @patterns = [] if @patterns.nil?
        @patterns << Regexp.new(pattern)
        return self
    end

    def patterns
        return @patterns if @patterns
        return []
    end

    def add_range(range)
        def interpret_bound(bound)
            if bound == 'max'
                @ranges.max_by {|r| r.max}.max
            elsif bound == 'min'
                @ranges.min_by {|r| r.min}.min
            elsif @name == 'decimal64'
                BigDecimal(bound)
            elsif @name =~ /u?int\d{1,2}/
                Integer(bound)
            elsif ['string', 'binary'].include? @name
                Integer(bound)
            end
        end

        @ranges = range.split('|').map do |range|
            min, max = range.split('..').map(&:strip)
            max = min if max.nil?
            Range.new(interpret_bound(min), interpret_bound(max))
        end

        return self
    end

    def add_length(length)
        add_range(length)
    end

    def length
        @ranges
    end

    def set_fraction_digits(fraction_digits)
        return self if @name != 'decimal64'
        @fraction_digits = fraction_digits
        min = BigDecimal("-9223372036854775808") / (10 ** fraction_digits)
        max = BigDecimal("9223372036854775807") / (10 ** fraction_digits)
        @ranges = [Range.new(min, max)]
        return self
    end

    def restrict_bits(bits)
        return self if @name != 'bits'

        t = Type.new(@name)
        t.bits = {}

        bits.each do |b|
            if @bits[b.name]
                if b.position == @bits[b.name].position
                    t.bits[b.name] = b
                elsif b.position.nil?
                    b.position = @bits[b.name].position
                    t.bits[b.name] = b
                else
                    #TODO: exception
                    puts "Invalid bit restriction, bit #{b.name} has changed position from #{@bits[b.name].position} to #{b.position}"
                end
            else
                #TODO: exception
                puts "Invalid bit restriction, bit #{b.name} doesn't exist in base type"
            end
        end

        return t
    end

    def restrict_enums(enums)
        return self if @name != 'enumeration'

        t = Type.new(@name)
        t.enums = {}

        enums.each do |e|
            if @enums[e.name]
                if e.value == @enums[e.name].value
                    t.enums[e.name] = e
                elsif e.value.nil?
                    e.value = @enums[b.name].value
                    t.enums[e.name] = e
                else
                    #TODO: exception
                    puts "Invalid enum restriction, enum #{e.name} has changed value from #{@enums[e.name].value} to #{e.value}"
                end
            else
                #TODO: exception
                puts "Invalid enum restriction, enum #{e.name} doesn't exist in base type"
            end
        end

        return t
    end
end

class Universe < Type
    def restrict_enums(enums)
        return self if @name != 'enumeration'

        t = Type.new(@name)
        t.enums = {}

        enums.each do |enum|
            if enum.value.nil?
                enum.value = 0
                _, e = t.enums.max_by {|_, e| e.value}
                enum.value = e.value + 1 if e
            end

            t.enums[enum.name] = enum
        end

        return t
    end

    def restrict_bits(bits)
        return self if @name != 'bits'

        t = Type.new(@name)
        t.bits = {}

        bits.each do |bit|
            if bit.position.nil?
                bit.position = 0
                _, b = t.bits.max_by {|_, b| b.position}
                bit.position = b.position + 1 if b
            end

            t.bits[bit.name] = bit
        end

        return t
    end
end

class Identity
    attr_reader   :name, :mod, :base, :derived
    attr_accessor :sid

    def initialize(name, mod)
        @name = name
        @mod  = mod
        @base = []
        @derived = []
    end

    # Returns the transitive closure of the derivation relation starting with this identity.
    # See RFC 7950 section 7.18.2.
    def derived_from
        @derived + @derived.flat_map(&:derived_from)
    end
end

Bit   = Struct.new(:name, :position, :description)
Enum  = Struct.new(:name, :value, :description)
Range = Struct.new(:min, :max) {
    def include?(x)
        min <= x and x <= max
    end
}

SCHEMA_NODES = ['action', 'container', 'leaf', 'leaf-list', 'list', 'choice', 'case', 'rpc', 'input', 'output', 'notification', 'anydata', 'anyxml']
DATA_NODES = ['container', 'leaf', 'leaf-list', 'list', 'anydata', 'anyxml']
IMPLICIT_CASE_NODES = ['anydata', 'anyxml', 'choice', 'container', 'leaf', 'list', 'leaf-list']
BUILTIN_TYPES = ['binary', 'bits', 'boolean', 'decimal64', 'empty', 'enumeration', 'identityref', 'instance-identifier', 'int8', 'int16', 'int32', 'int64', 'leafref', 'string', 'uint8', 'uint16', 'uint32', 'uint64', 'union']

end
