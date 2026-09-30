cmake_minimum_required(VERSION 3.13)
project(cmsis_dap_plugin C)

find_package(Wireshark REQUIRED)

add_library(cmsis_dap MODULE
  packet-cmsis-dap.c
  plugin.c
)

set_target_properties(cmsis_dap PROPERTIES
  PREFIX ""
  OUTPUT_NAME "cmsis_dap"
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
)

target_link_libraries(cmsis_dap PRIVATE epan)

install(TARGETS cmsis_dap
  LIBRARY DESTINATION "lib/wireshark/plugins/${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}/epan"
)
