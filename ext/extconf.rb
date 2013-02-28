
require 'mkmf'

Config::CONFIG['CC'] = 'g++'
Config::CONFIG['CPP'] = 'g++ -E'

# hack to get C++ standard library properly linked into shared
# object
# $libs = append_library($libs, "supc++") # doesn't work
if Config::CONFIG["arch"] =~ /-darwin\d/
  Config::CONFIG['LDSHARED']="g++ -dynamic -bundle -undefined suppress -flat_namespace"
else
  Config::CONFIG['LDSHARED'] = "g++ -shared"
end

$CFLAGS << " -DNDEBUG -DCRYPTOPP_DISABLE_ASM"

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
