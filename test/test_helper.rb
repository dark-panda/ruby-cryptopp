
require 'rubygems'
require 'minitest/autorun'
require 'minitest/reporters' if RUBY_VERSION >= '1.9'
require File.join(File.dirname(__FILE__), %w{ .. ext cryptopp })

puts "Version #{CryptoPP::VERSION}"
puts "Crypto++ version #{CryptoPP::CRYPTOPP_VERSION}"

module TestHelper
  def readfile(file)
    File.open(file) do |f|
      while !f.eof do
        l = f.gets.strip.split "\t"
        case l.shift
          when 'algorithm'
            type = l.shift.upcase
            algorithm = l.shift.to_sym
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
                  options[:block_mode] = l.shift.to_sym
                when 'padding'
                  options[:padding] = l.shift.to_sym
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

if RUBY_VERSION >= '1.9'
  MiniTest::Reporters.use!(MiniTest::Reporters::SpecReporter.new)
end

