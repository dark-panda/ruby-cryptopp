
begin
	require "#{File.dirname(__FILE__)}/../../ext/cryptopp"
rescue
	require "#{File.dirname(__FILE__)}/../../lib/cryptopp"
end

require 'test/unit'

