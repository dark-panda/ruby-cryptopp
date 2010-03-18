
require 'test/unit'
require 'test/test_helper'

class HMACsTest < Test::Unit::TestCase
	include TestHelper

	Dir.glob('test/data/hmacs/*.dat').sort.each do |f|
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
