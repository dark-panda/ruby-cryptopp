
require 'rubygems'
require 'minitest/autorun'
require 'minitest/reporters' if RUBY_VERSION >= '1.9'
require 'yaml'
require File.join(File.dirname(__FILE__), %w{ .. ext cryptopp })

puts "Version #{CryptoPP::VERSION}"
puts "Crypto++ version #{CryptoPP::CRYPTOPP_VERSION}"

module TestHelper
  def readfile(file)
    File.open(file) do |f|
      yaml = YAML.load(f.read)

      yaml.each_with_index do |options, i|
        if options[:plaintext_repeat]
          value = options[:plaintext] || options[:plaintext_hex]
          value.replace(value * options[:plaintext_repeat])
        end

        if options[:key_repeat]
          value = options[:key] || options[:key_hex]
          value.replace(value * options[:key_repeat])
        end

        yield(options, i)
      end
    end
  end
end

if RUBY_VERSION >= '1.9'
  MiniTest::Reporters.use!(MiniTest::Reporters::SpecReporter.new)
end

