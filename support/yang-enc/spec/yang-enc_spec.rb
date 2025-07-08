# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

require 'yang-enc'

RSpec.shared_context 'shared test data' do
    let(:alarm_state) {
        Yang::Universe.new('bits').restrict_bits([
            Yang::Bit.new('unknown'),
            Yang::Bit.new('under-repair'),
            Yang::Bit.new('critical'),
            Yang::Bit.new('major'),
            Yang::Bit.new('minor'),
            Yang::Bit.new('warning', 8),
            Yang::Bit.new('indeterminate', 128)
        ])
    }

    let(:oper_status) {
        Yang::Universe.new('enumeration').restrict_enums([
            Yang::Enum.new('up', 1),
            Yang::Enum.new('down', 2),
            Yang::Enum.new('testing', 3),
            Yang::Enum.new('unknown', 4),
            Yang::Enum.new('dormant', 5),
            Yang::Enum.new('not-present', 6),
            Yang::Enum.new('lower-layer-down', 7)
        ])
    }

    let(:interface_type) {
        ethernetCsmacd = Yang::Identity.new('ethernetCsmacd', 'iana-if-type')
        ethernetCsmacd.sid = 1880

        iana_if_type = Yang::Identity.new('iana-interface-type', 'iana-if-type')
        iana_if_type.derived << ethernetCsmacd

        if_type = Yang::Identity.new('interface-type', 'ietf-interfaces')
        if_type.derived << iana_if_type

        identityref = Yang::Type.new 'identityref'
        identityref.deref = [if_type]
        identityref.mod = 'ietf-interfaces'
        identityref
    }

    let(:ipv4) {
        Yang::Type.new('string')
        .add_pattern('(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(%[\p{N}\p{L}]+)?')
    }

    let(:ipv6) {
        Yang::Type.new('string')
        .add_pattern('((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(%[\p{N}\p{L}]+)?')
        .add_pattern('(([^:]+:){6}(([^:]+:[^:]+)|(.*\..*)))|((([^:]+:)*[^:]+)?::(([^:]+:)*[^:]+)?)(%.+)?')
    }
end

RSpec.shared_context 'yang catalog' do
    let(:yang_schema) {
        yang_schema_get
    }
end

RSpec.describe 'type2cbor' do
    include_context 'shared test data'

    it 'converts integers smaller than 64-bit to themselves' do
        expect(type2cbor(Yang::Type.new('uint16'), 1280)).to eq 1280
        expect(type2cbor(Yang::Type.new('int16'), -300)).to eq -300
    end

    it 'converts 64-bit integers from strings to integers' do
        expect(type2cbor(Yang::Type.new('int64'), '-438325023')).to eq -438325023
    end

    it "converts 'empty' to nil" do
        expect(type2cbor(Yang::Type.new('empty'), [nil])).to eq nil
    end

    it 'converts strings and booleans to themselves' do
        expect(type2cbor(Yang::Type.new('string'), 'eth0')).to eq 'eth0'
        expect(type2cbor(Yang::Type.new('boolean'), true)).to eq true
    end

    it 'decodes base64 encoded binary data' do
        aes128 = ['1f1ce6a3f42660d888d92a4d8030476e'].pack('H*')
        expect(type2cbor(Yang::Type.new('binary'), Base64.encode64(aes128))).to eq aes128
    end

    it "converts 'leafref' values according to the type of the leaf that's referred to" do
        leaf = Yang::Statement.new('leaf', 'name')
        leaf.type = Yang::Type.new 'string'
        type = Yang::Type.new 'leafref'
        type.deref = leaf
        expect(type2cbor(type, 'eth1')).to eq 'eth1'
    end

    it 'converts a decimal64 value with n (implicit) fraction digits to scientific notation with an exponent of -n' do
        type = Yang::Type.new 'decimal64'
        type.set_fraction_digits 2
        expect(type2cbor(type, '2.57')).to eq CBOR::Tagged.new(4, [-2, 257])
        expect(type2cbor(type, '25.7')).to eq CBOR::Tagged.new(4, [-2, 2570])
        expect(type2cbor(type, '257')).to eq CBOR::Tagged.new(4, [-2, 25700])
    end

    context 'inside a union' do
        it 'converts an enumeration value to a string with the tag 44' do
            enum = Yang::Universe.new('enumeration').restrict_enums([Yang::Enum.new('unbounded')])
            union = Yang::Type.new('union').add_member(Yang::Type.new 'int32').add_member(enum)

            expect(type2cbor(union, 'unbounded')).to eq CBOR::Tagged.new(44, 'unbounded')
        end

        it 'converts a bitset to a string with the names of the non-zero bits, tagged with 43' do
            bits = Yang::Universe.new('bits').restrict_bits([Yang::Bit.new('extra-flag')])
            union = Yang::Type.new('union').add_member(alarm_state).add_member(bits)

            expect(type2cbor(union, 'critical under-repair')).to eq CBOR::Tagged.new(43, 'critical under-repair')
        end

        it 'converts a reference to an identity to a SID, tagged with 45' do
            union =
                Yang::Type.new('union')
                .add_member(Yang::Type.new 'int32')
                .add_member(interface_type)

            expect(type2cbor(union, 'iana-if-type:ethernetCsmacd')).to eq CBOR::Tagged.new(45, 1880)
        end
    end

    context 'outside a union' do
        it 'converts an enumeration name to its corresponding integer value' do
            expect(type2cbor(oper_status, 'testing')).to eq 3
        end

        it 'converts a sparse bitset to an array of bytestrings and integer offsets' do
            expect(type2cbor(alarm_state, 'warning critical indeterminate')).to eq ["\x04\x01", 14, "\x01"]
            expect(type2cbor(alarm_state, 'indeterminate')).to eq [16, "\x01"]
            expect(type2cbor(alarm_state, '')).to eq []
        end

        it 'converts a dense bitset to a bytestring' do
            expect(type2cbor(alarm_state, 'critical under-repair')).to eq "\x06"
        end

        it 'converts a reference to an identity to a SID' do
            expect(type2cbor(interface_type, 'iana-if-type:ethernetCsmacd')).to eq 1880
        end
    end
end

RSpec.describe 'match_type_*' do
    include_context 'shared test data'

    it 'matches strings based on their pattern restrictions' do
        expect(match_type_json(ipv4, '2001:db8:a0b:12f0::1')).to be false
        expect(match_type_json(ipv6, '2001:db8:a0b:12f0::1')).to be true
        expect(match_type_cbor(ipv4, '2001:db8:a0b:12f0::1')).to be false
        expect(match_type_cbor(ipv6, '2001:db8:a0b:12f0::1')).to be true
    end

    it 'matches integers based on their range restrictions' do
        expect(match_type_json(Yang::Type.new('uint8'), -5)).to be false
        expect(match_type_json(Yang::Type.new('int8'), 300)).to be false
        expect(match_type_json(Yang::Type.new('int64'), '300')).to be true
        expect(match_type_json(Yang::Type.new('int64'), 300)).to be false
        expect(match_type_cbor(Yang::Type.new('uint8'), -5)).to be false
        expect(match_type_cbor(Yang::Type.new('int8'), 300)).to be false
        expect(match_type_cbor(Yang::Type.new('int64'), '300')).to be false
        expect(match_type_cbor(Yang::Type.new('int64'), 300)).to be true
    end

    it 'matches strings based on their length restrictions' do
        type = Yang::Type.new('string')
        type.add_length('0..4')
        expect(match_type_json(type, '')).to be true
        expect(match_type_json(type, 'AB')).to be true
        expect(match_type_json(type, '9A00')).to be true
        expect(match_type_json(type, '00ABAB')).to be false
        expect(match_type_cbor(type, '')).to be true
        expect(match_type_cbor(type, 'AB')).to be true
        expect(match_type_cbor(type, '9A00')).to be true
        expect(match_type_cbor(type, '00ABAB')).to be false
    end
end

RSpec.describe 'type2json' do
    include_context 'shared test data'

    it 'converts integers smaller than 64-bit to themselves' do
        expect(type2json(Yang::Type.new('uint16'), 1280)).to eq 1280
        expect(type2json(Yang::Type.new('int16'), -300)).to eq -300
    end

    it 'converts 64-bit integers from integers to strings' do
        expect(type2json(Yang::Type.new('int64'), -438325023)).to eq '-438325023'
    end

    it "converts 'empty' to an array with a single nil" do
        expect(type2json(Yang::Type.new('empty'), nil)).to eq [nil]
    end

    it 'converts strings and booleans to themselves' do
        expect(type2json(Yang::Type.new('string'), 'eth0')).to eq 'eth0'
        expect(type2json(Yang::Type.new('boolean'), true)).to eq true
    end

    it 'base64 encodes binary data' do
        aes128 = ['1f1ce6a3f42660d888d92a4d8030476e'].pack('H*')
        expect(type2json(Yang::Type.new('binary'), aes128)).to eq Base64.strict_encode64(aes128)
    end

    it "converts 'leafref' values according to the type of the leaf that's referred to" do
        leaf = Yang::Statement.new('leaf', 'name')
        leaf.type = Yang::Type.new 'string'
        type = Yang::Type.new 'leafref'
        type.deref = leaf
        expect(type2json(type, 'eth1')).to eq 'eth1'
    end

    it 'converts a decimal64 value i * 10^-n represented as [-n, i] to canonical form (see RFC 7951 section 9.3.2)' do
        type = Yang::Type.new 'decimal64'
        type.set_fraction_digits 2
        expect(type2json(type, CBOR::Tagged.new(4, [-2, 257]))).to eq '2.57'
        expect(type2json(type, CBOR::Tagged.new(4, [-2, 2570]))).to eq '25.7'
        expect(type2json(type, CBOR::Tagged.new(4, [-2, 25700]))).to eq '257.0'
        expect(type2json(type, CBOR::Tagged.new(4, [-2, 0]))).to eq '0.0'
    end

    it 'converts a enumeration value to an enum name' do
        enum = Yang::Universe.new('enumeration').restrict_enums([Yang::Enum.new('unbounded')])
        union = Yang::Type.new('union').add_member(Yang::Type.new 'int32').add_member(enum)

        expect(type2json(union, CBOR::Tagged.new(44, 'unbounded'))).to eq 'unbounded'
        expect(type2json(oper_status, 3)).to eq 'testing'
    end

    it 'converts a bitset to a string naming the non-zero bits' do
        bits = Yang::Universe.new('bits').restrict_bits([Yang::Bit.new('extra-flag')])
        union = Yang::Type.new('union').add_member(alarm_state).add_member(bits)

        expect(type2json(union, CBOR::Tagged.new(43, 'critical under-repair'))).to eq 'critical under-repair'
        expect(type2json(alarm_state, ["\x04\x01", 14, "\x01"])).to eq 'critical warning indeterminate'
        expect(type2json(alarm_state, "\x06")).to eq 'under-repair critical'
        expect(type2json(alarm_state, [16, "\x01"])).to eq 'indeterminate'
        expect(type2json(alarm_state, [])).to eq ''
        expect(type2json(alarm_state, "".b)).to eq ''
    end

    it "converts an 'identityref' SID into the name of a derived identity" do
        union =
            Yang::Type.new('union')
            .add_member(Yang::Type.new 'int32')
            .add_member(interface_type)

        expect(type2json(union, CBOR::Tagged.new(45, 1880))).to eq 'iana-if-type:ethernetCsmacd'
        expect(type2json(interface_type, 1880)).to eq 'iana-if-type:ethernetCsmacd'
    end
end

RSpec.describe 'json_seq2cbor and cbor_seq2json' do
    include_context 'yang catalog'

    it "check fetch-req.yaml <-> fetch-req.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'fetch-req.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'fetch-req.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'fetch')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'fetch')).to eq yaml
    end

    it "check fetch-res.yaml <-> fetch-res.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'fetch-res.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'fetch-res.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'fetch')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'fetch')).to eq yaml
    end

    it "check fetch-req-port-get.yaml <-> fetch-req-port-get.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'fetch-req-port-get.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'fetch-req-port-get.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'fetch')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'fetch')).to eq yaml
    end

    it "check fetch-resp-port-get.yaml <-> fetch-resp-port-get.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'fetch-resp-port-get.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'fetch-resp-port-get.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'fetch')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'fetch')).to eq yaml
    end

    it "check ipatch-req.yaml <-> ipatch-req.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'ipatch-req.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'ipatch-req.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'ipatch')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'ipatch')).to eq yaml
    end

    it "check ipatch-req-set-ip.yaml <-> ipatch-req-set-ip.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'ipatch-req-set-ip.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'ipatch-req-set-ip.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'ipatch')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'ipatch')).to eq yaml
    end

    it "check post-req.yaml <-> post-req.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'post-req.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'post-req.cbor'))
        expect(json_seq2cbor(yang_schema, yaml, 'post')).to eq cbor
        expect(cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'post')).to eq yaml
    end

    it "check ipatch-port-speed.yaml <-> ipatch-port-speed.cbor" do
        yaml = YAML.load(File.read(File.join(__dir__, 'tests', 'ipatch-port-speed.yaml')))
        cbor = File.binread(File.join(__dir__, 'tests', 'ipatch-port-speed.cbor'))
        yaml_canonical = cbor_seq2json(yang_schema, CBOR.decode_seq(cbor), 'ipatch')
        expect(json_seq2cbor(yang_schema, yaml_canonical, 'ipatch')).to eq cbor
        expect(json_seq2cbor(yang_schema, yaml, 'ipatch')).to eq cbor
    end
end

RSpec.describe 'iid2cbor' do
    include_context 'yang catalog'

    it "converts keys to CBOR in the order specified by the YANG not the instance identifier" do
        iid, s = iid2cbor(yang_schema, "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[name='børge'][type='routing-protocol']")
        expect(iid.size).to eq 3
        expect(iid[1]).to eq 12006
        expect(iid[2]).to eq 'børge'
    end

    it "raises an error if keys are specified on a non-list element" do
      expect { iid2cbor(yang_schema, "/ietf-routing:routing/control-plane-protocols[name='børge'][type='routing-protocol']/control-plane-protocol") }.to raise_error(RuntimeError)
    end

    it "raises an error if non-existing keys are specified on a list element" do
      expect { iid2cbor(yang_schema, "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='routing-protocol'][kage=0]") }.to raise_error(RuntimeError)
    end

    it "raises an error if keys are duplicated" do
      expect { iid2cbor(yang_schema, "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='routing-protocol'][type=0]") }.to raise_error(RuntimeError)
    end
end
