if(NOT DEFINED MONITOR OR NOT DEFINED TEST_DIR)
    message(FATAL_ERROR "MONITOR and TEST_DIR are required")
endif()

# Every executable invocation below is --help or a deliberately invalid CLI.
# There is no valid-duration-only invocation and no device/SCM/driver test.
function(expect_invalid name expected)
    execute_process(COMMAND "${MONITOR}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors
        TIMEOUT 5 WORKING_DIRECTORY "${TEST_DIR}")
    set(text "${output}${errors}")
    if(NOT result STREQUAL "2")
        message(FATAL_ERROR "${name}: expected parser exit 2, got ${result}: ${text}")
    endif()
    if(NOT text MATCHES "${expected}")
        message(FATAL_ERROR "${name}: missing expected diagnostic '${expected}': ${text}")
    endif()
    if(text MATCHES "Opening explicitly installed|Driver version")
        message(FATAL_ERROR "${name}: invalid CLI reached the device path: ${text}")
    endif()
endfunction()

expect_invalid(zero_duration "positive decimal" --duration 0)
expect_invalid(negative_duration "positive decimal" --duration -1)
expect_invalid(overflow_duration "positive decimal" --duration 4294967296)
expect_invalid(junk_duration "positive decimal" --duration 10x)
expect_invalid(missing_duration "positive decimal" --duration)
expect_invalid(bad_poll "positive decimal" --duration 1 --poll 0)
expect_invalid(bad_poll_negative "positive decimal" --duration 1 --poll -1)
expect_invalid(bad_protocol "0 to 255" --duration 1 --filter-protocol 256)
expect_invalid(pid_filter_zero_rejected "unknown option" --duration 1 --filter-pid 0)
expect_invalid(pid_filter_nonzero_rejected "unknown option" --duration 1 --filter-pid 1234)
expect_invalid(pid_filter_missing_rejected "unknown option" --duration 1 --filter-pid)
expect_invalid(bad_match "without --verdict" --duration 1 --match 192.0.2.1)
expect_invalid(bad_port "1 to 65535" --duration 1 --verdict block --match 192.0.2.1:65536)
expect_invalid(bad_ipv6_port "1 to 65535" --duration 1 --filter-ip "[::1]:53x")
expect_invalid(bad_delay "0 to 4294967295" --duration 1 --verdict-delay-ms 4294967296)
expect_invalid(suspend_rejected "PID suspension is not supported" --duration 1 --suspend-pid-on-verdict-delay)
expect_invalid(sys_rejected "SCM installation is not supported" --duration 1 --sys ignored.sys)
expect_invalid(positional_rejected "positional driver path" --duration 1 ignored.sys)
expect_invalid(update_v4_rejected "unknown option" --duration 1 --update-v4)
expect_invalid(update_v6_rejected "unknown option" --duration 1 --update-v6)
expect_invalid(pipe_rejected "unknown option" --duration 1 --pipe)
expect_invalid(winrpc_rejected "unknown option" --duration 1 --winrpc)
foreach(redirect IN ITEMS redirect-tunnel redirect-split redirect-dns redirect-name-server
                           redirect-split-tunnel redirect redirect-unknown)
    expect_invalid("${redirect}" "redirect verdicts are not supported" --duration 1 --verdict "${redirect}")
endforeach()

set(output_path "${TEST_DIR}/invalid-cli-must-not-create.log")
if(EXISTS "${output_path}")
    message(FATAL_ERROR "No-output assertion needs an absent path: ${output_path}")
endif()
expect_invalid(no_file_before_validation "redirect verdicts are not supported"
    --out "${output_path}" --duration 1 --verdict redirect-tunnel)
if(EXISTS "${output_path}")
    message(FATAL_ERROR "Invalid CLI created an output file before validation")
endif()

execute_process(COMMAND "${MONITOR}" --help
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors TIMEOUT 5
    WORKING_DIRECTORY "${TEST_DIR}")
if(NOT result STREQUAL "0" OR NOT output MATCHES "direction=0 outbound, 1 inbound" OR
   NOT output MATCHES "relative to the guest side" OR NOT output MATCHES "local=guest endpoint" OR
   NOT output MATCHES "Host receive=outbound, send=inbound" OR
   NOT output MATCHES "Redirects are NOT supported" OR
   NOT output MATCHES "Without --duration, wait for driver startup" OR
   NOT output MATCHES "Ctrl\\+C exits" OR
   NOT output MATCHES "never wait for driver startup" OR
   NOT output MATCHES "complete logical IP packet" OR
   NOT output MATCHES "up to 1 MiB, no truncation" OR
   NOT output MATCHES "Connection events carry no process/thread identity" OR
   output MATCHES "--filter-pid|PID=0|possibly shortened" OR
   output MATCHES "HyperVXNdisFilterPipe|Bridge:|winrpc|named-pipe" OR
   output MATCHES "Opening explicitly installed|Driver version")
    message(FATAL_ERROR "Help did not stay on the no-device path: ${result}: ${output}${errors}")
endif()
message(STATUS "PASS: bounded help/invalid CLI checks, early redirect rejection, no output/device/SCM access")
