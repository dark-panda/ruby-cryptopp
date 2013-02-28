
require 'mkmf'
require 'rbconfig'

RbConfig::CONFIG['CC'] = 'g++'
RbConfig::CONFIG['CPP'] = 'g++ -E'

# hack to get C++ standard library properly linked into shared
# object
# $libs = append_library($libs, "supc++") # doesn't work
if RbConfig::CONFIG["arch"] =~ /-darwin\d/
  $warnflags << ' -Wno-shorten-64-to-32' if $warnflags
  RbConfig::CONFIG['LDSHARED'] = "g++ -dynamic -bundle -undefined suppress -flat_namespace"
else
  RbConfig::CONFIG['LDSHARED'] = "g++ -shared"
end

version = File.read(File.join(File.dirname(__FILE__), *%w{ .. VERSION })).strip
$CFLAGS << " -DNDEBUG -DCRYPTOPP_DISABLE_ASM -DRUBY_VERSION_CODE=#{RbConfig::CONFIG.values_at('MAJOR', 'MINOR', 'TEENY').join}"
$CFLAGS << " -DEXT_VERSION_CODE=#{version}"

def error msg
  message msg + "\n"
  abort
end

unless have_library('stdc++')
  error "Can't find libstdc++"
end

unless have_library('cryptopp')
  error "Can't find cryptopp library"
end

unless find_header('cryptlib.h', *%w{
  /usr/local/include/cryptopp
  /usr/include/cryptopp
  /opt/local/include/cryptopp
})
  error "Can't find cryptlib.h"
end

create_makefile('cryptopp')
