
# -*- ruby -*-

require 'rubygems'
require 'rake/gempackagetask'
require 'rake/testtask'
require 'rake/rdoctask'

$:.push 'lib'

begin
    require 'jeweler'
    Jeweler::Tasks.new do |gem|
        gem.name        = "cryptopp"
        gem.version     = "0.0.4"
        gem.summary     = "cryptopp is a cryptographic library for Ruby built on Wei Dai's Crypto++."
        gem.description = gem.summary
        gem.email       = "dark.panda@gmail.com"
        gem.homepage    = "http://github.com/dark-panda/cryptopp"
        gem.authors =    [ "J Smith" ]
    end
    Jeweler::GemcutterTasks.new
rescue LoadError
    puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

desc 'Test cryptopp interface'
Rake::TestTask.new(:test) do |t|
    t.libs << 'lib'
    t.pattern = 'test/**/*_test.rb'
    t.verbose = false
end

desc 'Build docs'
Rake::RDocTask.new do |t|
    require 'rdoc/rdoc'
    require 'extras/parser_c.rb'
    t.main = 'README'
    t.rdoc_dir = 'doc'
    t.rdoc_files.include('ext/cryptopp.cpp', 'ext/ciphers.cpp', 'ext/digests.cpp')
end

begin
	require 'rubygems'
	require 'rake/gempackagetask'
rescue Exception
	nil
end

