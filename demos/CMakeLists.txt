# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------
option(BUILD_USEFUL_DEMOS "Build useful demos (hashsum)" FALSE)
option(
    BUILD_USABLE_DEMOS
    "Build usable demos (aesgcm constants crypt openssh-privkey openssl-enc pem-info sizes timing)"
    FALSE
)
option(BUILD_TEST_DEMOS "Build test demos (small tv_gen)" FALSE)

option(INSTALL_DEMOS "Install enabled demos (USEFUL and/or USABLE) and ltc wrapper script" FALSE)

# -----------------------------------------------------------------------------
# Useful demos
#
# Demos that are even somehow useful and could be installed as a system-tool
#
# * USEFUL_DEMOS   = hashsum
# -----------------------------------------------------------------------------

if(BUILD_USEFUL_DEMOS)
    list(APPEND USABLE_DEMOS_TARGETS hashsum)
endif()

# -----------------------------------------------------------------------------
# Usable demos
#
# Demos that are usable but only rarely make sense to be installed
#
# USEABLE_DEMOS  = aesgcm constants crypt der_print_flexi openssh-privkey openssl-enc pem-info sizes timing x509_verify
# -----------------------------------------------------------------------------

if(BUILD_USABLE_DEMOS)
    list(
        APPEND
        USABLE_DEMOS_TARGETS
        aesgcm
        constants
        crypt
        der_print_flexi
        openssh-privkey
        openssl-enc
        pem-info
        sizes
        timing
        x509_verify
    )
endif()

# -----------------------------------------------------------------------------
# Test demos
#
# Demos that are used for testing or measuring
#
# * TEST_DEMOS     = small tv_gen
# -----------------------------------------------------------------------------

if(BUILD_TEST_DEMOS)
    list(APPEND ALL_DEMOS_TARGETS small tv_gen)
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
