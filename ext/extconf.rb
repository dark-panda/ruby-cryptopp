
require 'mkmf'
require 'rbconfig'

if RbConfig::CONFIG["arch"] =~ /-darwin\d/
  if $warnflags
    $warnflags << ' -Wno-shorten-64-to-32'
    $warnflags.gsub!('-Wdeclaration-after-statement', '')
    $warnflags.gsub!('-Wimplicit-function-declaration', '')
  end

  CONFIG["CXX"] = "clang++"
elsif RbConfig::CONFIG["arch"] =~ /x86_64-(freebsd|linux)/
  $LDFLAGS << " -fPIC -shared"
else
  $LDFLAGS << " -shared"
end

version = File.read(File.join(File.dirname(__FILE__), *%w{ .. VERSION })).strip
ruby_version = RbConfig::CONFIG.values_at('MAJOR', 'MINOR', 'TEENY').join

$defs.concat([
  "-DNDEBUG",
  "-DCRYPTOPP_DISABLE_ASM",
  "-DRUBY_VERSION_CODE=#{ruby_version}",
  "-DEXT_VERSION_CODE=#{version}"
])

def error msg
  message msg + "\n"
  abort
end

dir_config('cryptopp')

unless find_library('cryptopp', nil, *%w{
  /usr/local/lib
  /usr/local/lib/cryptopp
  /opt/local/lib
  /opt/local/lib/cryptopp
  /usr/lib
  /usr/lib/cryptopp
})
  error "Can't find cryptopp library"
end

# For the C++ headers, we need to compile using a C++ compiler since the header
# files can't compile cleanly in C.
puts "NOTE: The following warning is NORMAL due to an mkmf hack."

if defined?(MakeMakefile)
  MakeMakefile::CONFTEST_C = 'conftest.cc'
else
  CONFTEST_C = 'conftest.cc'
end

unless find_header('cryptlib.h', *%w{
  /usr/local/include
  /usr/local/include/cryptopp
  /opt/local/include
  /opt/local/include/cryptopp
  /usr/include
  /usr/include/cryptopp
})
  error "Can't find cryptlib.h"
end

create_makefile('cryptopp')

