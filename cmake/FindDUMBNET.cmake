###################################################################

#
#  DUMBNET_INCLUDE_DIR - where to find dnet.h, etc.
#  DUMBNET_LIBRARIES   - List of libraries when using dnet.
#  DUMBNET_FOUND       - True if dnet found.
#  HAVE_LIBDUMBNET      - True if found dumbnet

find_path(DUMPNET_ROOT_DIR
    NAMES include/dumbnet.h Include/dumbnet.h
)

find_path(DUMBNET_INCLUDE_DIR
    NAMES dumbnet.h
    HINTS ${DUMPNET_ROOT_DIR}/include
)

if ( MSVC AND COMPILER_ARCHITECTURE STREQUAL "x86_64" )
    set(_dumbnet_lib_hint_path ${DUMPNET_ROOT_DIR}/lib/x64)
else()
    set(_dumbnet_lib_hint_path ${DUMPNET_ROOT_DIR}/lib)
endif()

find_library(DUMBNET_LIBRARY
    NAMES dumbnet
    HINTS ${_dumbnet_lib_hint_path}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DUMBNET DEFAULT_MSG
    DUMBNET_LIBRARY
    DUMBNET_INCLUDE_DIR
)

mark_as_advanced(
    DUMPNET_ROOT_DIR
    DUMBNET_INCLUDE_DIR
    DUMBNET_LIBRARY
)

set(HAVE_LIBDUMBNET True)

message(STATUS "DUMBNET_INCLUDE_DIR ${DUMBNET_INCLUDE_DIR}")
message(STATUS "DUMBNET_LIBRARY ${DUMBNET_LIBRARY}")

add_library(dumbnet SHARED IMPORTED)
set_property(TARGET dumbnet PROPERTY
             IMPORTED_LOCATION "${DUMBNET_LIBRARY}")
target_include_directories(pcap INTERFACE ${DUMBNET_INCLUDE_DIR})
