
cmake_minimum_required(VERSION 2.8)

project(BroPluginbacnet)

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

if ( WORDS_BIGENDIAN )
  add_definitions(-DWORDS_BIGENDIAN)
endif ()

include(BroPlugin)

bro_plugin_begin(Heller bacnet)
bro_plugin_cc(src/bacnet.cc src/Plugin.cc)
bro_plugin_bif(src/events.bif src/consts.bif src/types.bif)
bro_plugin_pac(src/bacnet.pac src/bacnet-protocol.pac src/bacnet-analyzer.pac)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
