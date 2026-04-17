# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------

option(INSTALL_DEMOS "Install enabled demos (USEFUL and/or USABLE) and ltc wrapper script" FALSE)

# -----------------------------------------------------------------------------
# Useful demos
#
# Demos that are even somehow useful and could be installed as a system-tool
#
# -----------------------------------------------------------------------------
set(USEFUL_DEMOS hashsum)
list(JOIN USEFUL_DEMOS " " USEFUL_DEMOS_STR)
option(BUILD_USEFUL_DEMOS "Build useful demos (${USEFUL_DEMOS_STR})" FALSE)

if(BUILD_USEFUL_DEMOS)
    list(APPEND USABLE_DEMOS_TARGETS ${USEFUL_DEMOS})
endif()

# -----------------------------------------------------------------------------
# Usable demos
#
# Demos that are usable but only rarely make sense to be installed
#
# -----------------------------------------------------------------------------
set(USABLE_DEMOS aesgcm constants crypt der_print_flexi latex-tables openssh-privkey openssl-enc sizes timing x509_verify)
list(JOIN USABLE_DEMOS " " USABLE_DEMOS_STR)
option(BUILD_USABLE_DEMOS "Build usable demos (${USABLE_DEMOS_STR})" FALSE)

if(BUILD_USABLE_DEMOS)
    list(APPEND USABLE_DEMOS_TARGETS ${USABLE_DEMOS})
endif()

# -----------------------------------------------------------------------------
# Test demos
#
# Demos that are used for testing or measuring
#
# -----------------------------------------------------------------------------
set(TEST_DEMOS small tv_gen)
list(JOIN TEST_DEMOS " " TEST_DEMOS_STR)
option(BUILD_TEST_DEMOS "Build test demos (${TEST_DEMOS_STR})" FALSE)

if(BUILD_TEST_DEMOS)
    list(APPEND ALL_DEMOS_TARGETS ${TEST_DEMOS})
endif()

# -----------------------------------------------------------------------------
# Generate executables
# -----------------------------------------------------------------------------

# USABLE_DEMOS can get installed, so they're prefixed with `ltc-`
foreach(target ${USABLE_DEMOS_TARGETS})
    list(APPEND ALL_DEMOS_INSTALL_TARGETS ltc-${target})

    add_executable(ltc-${target} ${CMAKE_CURRENT_SOURCE_DIR}/${target}.c)

    target_link_libraries(ltc-${target} PRIVATE ${PROJECT_NAME})
endforeach()

foreach(target ${ALL_DEMOS_TARGETS})
    add_executable(${target} ${CMAKE_CURRENT_SOURCE_DIR}/${target}.c)

    target_link_libraries(${target} PRIVATE ${PROJECT_NAME})
endforeach()

# -----------------------------------------------------------------------------
# Install targets
# -----------------------------------------------------------------------------
if(INSTALL_DEMOS)
    install(
        TARGETS ${ALL_DEMOS_INSTALL_TARGETS}
        COMPONENT "runtime"
        EXPORT ${TARGETS_EXPORT_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    # Also install the `ltc` wrapper script
    install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/ltc DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
