# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

# A FETCH/iPATCH/POST payload entry must be a map of a single instance path to
# its value. These tests cover the clear error reporting when it is not (the
# shape users most often get wrong in the request YAML).

require 'yang-enc'

RSpec.describe 'validate_instance_entry!' do
    it 'rejects a non-map (array) entry, naming the content format and got-type' do
        expect { validate_instance_entry!(['/some/path'], 'ipatch') }
            .to raise_error(/IPATCH entry must be a map of a single instance path.*got array/m)
    end

    it 'rejects a scalar entry' do
        expect { validate_instance_entry!('/some/path', 'post') }
            .to raise_error(/POST entry must be a map.*got String/m)
    end

    it 'rejects a null entry' do
        expect { validate_instance_entry!(nil, 'ipatch') }
            .to raise_error(/got null/)
    end

    it 'rejects an entry with more than one key/value pair, listing the keys' do
        expect { validate_instance_entry!({'/a' => 1, '/b' => 2}, 'ipatch') }
            .to raise_error(/exactly one key\/value pair.*got 2: \/a, \/b/m)
    end

    it 'rejects an empty map' do
        expect { validate_instance_entry!({}, 'fetch') }
            .to raise_error(/exactly one key\/value pair.*got 0/m)
    end

    it 'accepts a single-key map' do
        expect { validate_instance_entry!({'/some/path' => 42}, 'ipatch') }.not_to raise_error
        expect { validate_instance_entry!({'/some/path' => nil}, 'ipatch') }.not_to raise_error
    end
end

RSpec.describe 'json_seq2cbor rejects malformed instance entries' do
    let(:yang_schema) { yang_schema_get }
    let(:max_frame) { "/ietf-interfaces:interfaces/interface[name='1']/mchp-velocitysp-port:eth-port/config/max-frame-length" }

    it 'rejects an iPATCH entry with two key/value pairs' do
        expect { json_seq2cbor(yang_schema, [{'/a' => 1, '/b' => 2}], 'ipatch') }
            .to raise_error(/exactly one key\/value pair/)
    end

    it 'rejects an iPATCH entry that is not a map' do
        expect { json_seq2cbor(yang_schema, ['/just/a/string'], 'ipatch') }
            .to raise_error(/must be a map of a single instance path/)
    end

    it 'still accepts a well-formed single-entry iPATCH request' do
        expect { json_seq2cbor(yang_schema, [{max_frame => 9000}], 'ipatch') }.not_to raise_error
    end

    it 'still accepts a bare instance-identifier string in a FETCH request' do
        expect { json_seq2cbor(yang_schema, [max_frame], 'fetch') }.not_to raise_error
    end
end
