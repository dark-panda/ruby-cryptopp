
require 'test/unit'
require 'test/lib/test_helper'

class CiphersTest < Test::Unit::TestCase
	Dir.glob('test/data/ciphers/*.dat').sort.each do |f|
		test_name = File.basename(f).gsub(/.dat$/, '')

		class_eval(%{
			def test_#{test_name}
				run_cipher_test("#{f}")
			end
		})
	end

	def run_cipher_test(file)
		File.open(file) do |f|
			while !f.eof do
				l = f.gets.strip.split "\t"
				case l.shift
					when 'algorithm'
						type = l.shift
						algorithm = l.shift
						if CryptoPP.cipher_enabled? CryptoPP::Constants.const_get("#{algorithm}_CIPHER")
							algorithm = CryptoPP::Constants.const_get("#{algorithm}_CIPHER")
						else
							return
						end
					when 'fields'
						fields = l
					when 'test'
						options = { :algorithm => algorithm }
						fields.each do |i|
							case i
								when 'ciphertext_cont'
									options[:ciphertext] = l.join ''
								when 'ciphertext_hex_cont'
									options[:ciphertext_hex] = l.join ''
								when 'plaintext_repeat'
									options[:plaintext] || options[:plaintext_hex] *= l.shift.to_i
								when 'key_repeat'
									options[:key] || options[:key_hex] *= l.shift.to_i
								when 'block_mode'
									options[:block_mode] = CryptoPP::Constants.const_get("#{l.shift}_BLOCK_MODE")
								when 'padding'
									options[:padding] = CryptoPP::Constants.const_get("#{l.shift}_PADDING")
								else
									options[i.to_sym] = l.shift
							end
						end

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
	end
end
