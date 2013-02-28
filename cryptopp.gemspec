# -*- encoding: utf-8 -*-

version = File.read(File.expand_path('VERSION', File.dirname(__FILE__)))

Gem::Specification.new do |s|
  s.name = "cryptopp"
  s.version = version

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["J Smith"]
  s.description = %q{cryptopp is a cryptographic library for Ruby built on Wei Dai's Crypto++.}
  s.summary = s.description
  s.email = %q{dark.panda@gmail.com}
  s.extensions = ["ext/extconf.rb"]
  s.extra_rdoc_files = [
    "README"
  ]
  s.files = `git ls-files`.split($\)
  s.homepage = %q{http://github.com/dark-panda/ruby-cryptopp}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
end

