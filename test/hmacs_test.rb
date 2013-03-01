
$: << File.dirname(__FILE__)
require 'test_helper'

class HMACsTest < MiniTest::Unit::TestCase
  extend TestHelper

  Dir.glob('test/data/hmacs/*.yml').sort.each do |f|
    test_name = File.basename(f).gsub(/.yml$/, '')

    readfile(f) do |options, i|
      define_method("test_#{test_name}_#{i}") do
        if CryptoPP.digest_enabled? options[:algorithm]
          d = CryptoPP.hmac_factory(options[:algorithm], {
            :key_hex => options[:key_hex],
            :plaintext => options[:plaintext]
          })
          d.calculate

          t = CryptoPP.hmac_factory(options[:algorithm], {
            :digest => d.digest,
            :plaintext => d.plaintext,
            :key => d.key
          })

          assert(t.validate)
          assert_equal(d.digest_hex, options[:digest_hex])
        end
      end
    end
  end
end
