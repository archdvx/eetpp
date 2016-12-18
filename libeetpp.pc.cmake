prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@CMAKE_INSTALL_PREFIX@/lib@LIB_SUFFIX@
includedir=@CMAKE_INSTALL_PREFIX@/include

Name: libeetpp
Description: C++ library for EET
Version: 1.00.0

Requires: libssl libcrypto libcurl
Libs: -L${libdir} -leetpp
Cflags: -I${includedir}
