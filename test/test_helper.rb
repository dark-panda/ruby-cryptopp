
require 'rubygems'
require 'cryptopp'

module TestHelper
	def readfile(file)
		File.open(file) do |f|
			while !f.eof do
				l = f.gets.strip.split "\t"
				case l.shift
					when 'algorithm'
						type = l.shift.upcase
						algorithm = l.shift
						if CryptoPP.cipher_enabled? CryptoPP::Constants.const_get("#{algorithm}_#{type}")
							algorithm = CryptoPP::Constants.const_get("#{algorithm}_#{type}")
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

						yield(options)
				end
			end
		end
	end
end
