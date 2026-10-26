add_library(hyperv_xndis_filter_setup STATIC
    Management.cpp
    WindowsSetup.cpp
    Target.cpp
    Package.cpp
    DriverStore.cpp
)
target_include_directories(hyperv_xndis_filter_setup PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(hyperv_xndis_filter_setup PUBLIC cxx_std_20)
target_compile_definitions(hyperv_xndis_filter_setup PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 WINVER=0x0A00
)
target_link_libraries(hyperv_xndis_filter_setup PUBLIC
    ole32 oleaut32 uuid advapi32 wbemuuid iphlpapi setupapi newdev wintrust crypt32
)
set_target_properties(hyperv_xndis_filter_setup PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
if(MSVC)
    target_compile_options(hyperv_xndis_filter_setup PRIVATE /W4 /WX /permissive- /utf-8 /guard:cf)
endif()

foreach(tool IN ITEMS Install Uninstall)
    add_executable(hyperv_${tool} main.cpp)
    set_target_properties(hyperv_${tool} PROPERTIES OUTPUT_NAME ${tool}
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_link_libraries(hyperv_${tool} PRIVATE hyperv_xndis_filter_setup)
    if(tool STREQUAL "Uninstall")
        target_compile_definitions(hyperv_${tool} PRIVATE HYPERVXNDISFILTER_UNINSTALL)
    endif()
    if(MSVC)
        target_compile_options(hyperv_${tool} PRIVATE /W4 /WX /permissive- /utf-8 /guard:cf)
        # No elevation or initialization for help/invalid CLI. Mutating actions
        # check the elevated token explicitly and never launch a child shell.
        target_link_options(hyperv_${tool} PRIVATE /ENTRY:wmainCRTStartup
            "/MANIFESTUAC:level='asInvoker' uiAccess='false'" /DYNAMICBASE /NXCOMPAT /GUARD:CF)
    else()
        target_link_options(hyperv_${tool} PRIVATE -municode)
    endif()
endforeach()

if(BUILD_TESTING)
    foreach(test_name IN ITEMS management_console_tests management_package_tests management_driver_store_tests)
        add_executable(${test_name} "tests/${test_name}.cpp")
        target_link_libraries(${test_name} PRIVATE hyperv_xndis_filter_setup)
        set_target_properties(${test_name} PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        if(MSVC)
            target_compile_options(${test_name} PRIVATE /W4 /WX /permissive- /utf-8)
        endif()
    endforeach()
    add_test(NAME management_console_tests COMMAND management_console_tests)
    add_test(NAME management_package_tests COMMAND management_package_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/../HyperVXNdisFilter.inf" "${CMAKE_CURRENT_BINARY_DIR}")
    add_test(NAME management_driver_store_tests COMMAND management_driver_store_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/../HyperVXNdisFilter.inf" "${CMAKE_CURRENT_BINARY_DIR}")
    add_test(NAME management_cli_tests COMMAND "${CMAKE_COMMAND}"
        "-DINSTALL=$<TARGET_FILE:hyperv_Install>"
        "-DUNINSTALL=$<TARGET_FILE:hyperv_Uninstall>"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/management_cli_tests.cmake")
    set_tests_properties(management_console_tests management_package_tests management_driver_store_tests management_cli_tests
        PROPERTIES TIMEOUT 30 LABELS "no-driver" WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endif()
