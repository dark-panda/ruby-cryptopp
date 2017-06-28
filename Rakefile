# -*- encoding: utf-8 -*-

# -*- ruby -*-

require 'rubygems'
require 'rubygems/package_task'
require 'rake/testtask'
require 'rdoc/task'
require 'bundler/gem_tasks'

$:.push File.expand_path(File.dirname(__FILE__), 'lib')

version = File.read(File.expand_path('VERSION', File.dirname(__FILE__)))

desc 'Test CryptoPP interface'
Rake::TestTask.new(:test) do |t|
  t.test_files = FileList['test/**/*_test.rb']
  t.verbose = !!ENV['VERBOSE_TESTS']
  t.warning = !!ENV['WARNINGS']
end

task :default => :test

desc 'Build docs'
Rake::RDocTask.new do |t|
  t.title = "CryptoPP #{version}"
  t.main = 'README'
  t.rdoc_dir = 'doc'
  t.rdoc_files.include(
    'README',
    'MIT-LICENSE',
    'ext/cryptopp.cpp',
    'ext/ciphers.cpp',
    'ext/digests.cpp'
  )
end

