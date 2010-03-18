
require 'test/unit'
require 'test/test_helper'

class CiphersTest < Test::Unit::TestCase
	include TestHelper

	Dir.glob('test/data/ciphers/*.dat').sort.each do |f|
		test_name = File.basename(f).gsub(/.dat$/, '')

		class_eval(%{
			def test_#{test_name}
				run_cipher_test("#{f}")
			end
		})
	end

	def run_cipher_test(file)
		readfile(file) do |options|
			if CryptoPP.cipher_enabled? options[:algorithm]
				encryption_factory_options = options.reject do |k, v|
					[ :algorithm, :ciphertext, :ciphertext_hex ].include? k
				end
				encrypt = CryptoPP.cipher_factory options[:algorithm], encryption_factory_options

				decryption_factory_options = options.reject do |k, v|
					[ :algorithm, :plaintext, :plaintext_hex ].include? k
				end
				decrypt = CryptoPP.cipher_factory options[:algorithm], decryption_factory_options
				decrypt.decrypt

				assert_equal(decrypt.plaintext, encrypt.plaintext)
				assert_equal(decrypt.ciphertext_hex, options[:ciphertext_hex])
			end
		end
	end
end
