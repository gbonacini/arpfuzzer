bin_PROGRAMS   = arpfuzzer
dist_man_MANS  = ../doc/arpfuzzer.1

arpfuzzer_SOURCES = arpfuzzer_main.cpp arplib.cpp capabilities.cpp parseCmdLine.cpp fuzzer.cpp debug.cpp configFile.cpp StringUtilsImpl.cpp TypesImpl.cpp

nobase_include_HEADERS   = ../include/capabilities.hpp ../include/parseCmdLine.hpp ../include/parseCmdLine.hpp  ../include/fuzzer.hpp ../include/debug.hpp ../include/configFile.hpp ../include/StringUtils.hpp  ../include/Types.hpp ../include/StaticTypes.hpp 

arpfuzzer_CPPFLAGS         = ${LUA_INCLUDE}
arpfuzzer_LDADD            = ${LUA_LIB}

install-exec-hook:
	setcap cap_net_raw=eip  $(bindir)/arpfuzzer
