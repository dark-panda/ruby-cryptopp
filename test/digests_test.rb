
require 'test/unit'
require 'test/test_helper'

class DigestsTest < Test::Unit::TestCase
  include TestHelper

  Dir.glob('test/data/digests/*.dat').sort.each do |f|
    test_name = File.basename(f).gsub(/.dat$/, '')

    class_eval(%{
      def test_#{test_name}
        run_digest_test("#{f}")
      end
    })
  end

  def run_digest_test(file)
    readfile(file) do |options|
      if CryptoPP.digest_enabled? options[:algorithm]
        d = CryptoPP.digest_factory(options[:algorithm], options[:plaintext])
        t = CryptoPP.digest_factory(options[:algorithm], { :digest => d.digest, :plaintext => d.plaintext })

        assert(t.validate)
        assert_equal(d.digest_hex, options[:digest_hex])
      end
    end
  end
end
