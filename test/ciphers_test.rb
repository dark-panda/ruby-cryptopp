
$: << File.dirname(__FILE__)
require 'test_helper'

class CiphersTest < Minitest::Test
  extend TestHelper

  Dir.glob('test/data/ciphers/*.yml').sort.each do |f|
    test_name = File.basename(f).gsub(/.yml$/, '')

    readfile(f) do |options, i|
      define_method("test_#{test_name}_#{i}") do
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
