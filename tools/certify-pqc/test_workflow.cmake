if(NOT CERTIFY_PQC OR NOT WORK_DIRECTORY)
    message(FATAL_ERROR "CERTIFY_PQC and WORK_DIRECTORY are required")
endif()

file(REMOVE_RECURSE "${WORK_DIRECTORY}")
file(MAKE_DIRECTORY "${WORK_DIRECTORY}")

function(run)
    execute_process(
        COMMAND ${ARGV}
        WORKING_DIRECTORY "${WORK_DIRECTORY}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        string(JOIN " " command ${ARGV})
        message(FATAL_ERROR "Command failed (${result}): ${command}\n${output}${error}")
    endif()
endfunction()

function(run_fails)
    execute_process(
        COMMAND ${ARGV}
        WORKING_DIRECTORY "${WORK_DIRECTORY}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error)
    if(result EQUAL 0)
        string(JOIN " " command ${ARGV})
        message(FATAL_ERROR "Command unexpectedly succeeded: ${command}\n${output}${error}")
    endif()
endfunction()

function(check_show certificate material public_key_size signature_size)
    execute_process(
        COMMAND "${CERTIFY_PQC}" show "${certificate}"
        WORKING_DIRECTORY "${WORK_DIRECTORY}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Cannot inspect ${certificate}:\n${output}${error}")
    endif()

    set(expectations
        "Alternative material: ${material}"
        "FN-DSA-512 public key: ${public_key_size} bytes"
        "FN-DSA-512 signature: ${signature_size} bytes")
    foreach(expectation IN LISTS expectations)
        string(FIND "${output}" "${expectation}" position)
        if(position EQUAL -1)
            message(FATAL_ERROR
                "Unexpected material in ${certificate}: missing '${expectation}'\n${output}")
        endif()
    endforeach()
endfunction()

run("${CERTIFY_PQC}" generate-key root)
run("${CERTIFY_PQC}" generate-key aa)
run("${CERTIFY_PQC}" generate-key ticket --profile ecc)

run("${CERTIFY_PQC}" generate-root
    --profile ecc --output ecc-root.cert --subject-key root --days 365
    --aid 36 141)
run("${CERTIFY_PQC}" generate-aa
    --profile ecc --output ecc-aa.cert
    --sign-key root --sign-cert ecc-root.cert
    --subject-key aa --days 180
    --aid 36 141)
run("${CERTIFY_PQC}" generate-ticket
    --profile ecc --output ecc-ticket.cert
    --sign-key aa --sign-cert ecc-aa.cert
    --subject-key ticket --days 7
    --aid 141)
run("${CERTIFY_PQC}" verify-chain --profile ecc
    --root ecc-root.cert --aa ecc-aa.cert --ticket ecc-ticket.cert --aid 141)
check_show(ecc-root.cert "none" 0 0)
check_show(ecc-aa.cert "none" 0 0)
check_show(ecc-ticket.cert "none" 0 0)

run("${CERTIFY_PQC}" generate-root
    --output root.cert --subject-key root --subject-pqc-key root --days 365
    --aid 36 141)
run("${CERTIFY_PQC}" generate-aa
    --output aa.cert
    --sign-key root --sign-cert root.cert --sign-pqc-key root
    --subject-key aa --subject-pqc-key aa --days 180
    --aid 36 141)
run("${CERTIFY_PQC}" generate-ticket
    --output ticket.cert
    --sign-key aa --sign-cert aa.cert --sign-pqc-key aa
    --subject-key ticket --days 7
    --aid 141)
run("${CERTIFY_PQC}" verify-chain
    --root root.cert --aa aa.cert --ticket ticket.cert --aid 141)
check_show(root.cert "authority (key + signature)" 897 666)
check_show(aa.cert "authority (key + signature)" 897 666)
check_show(ticket.cert "end entity (signature only)" 0 666)

run_fails("${CERTIFY_PQC}" verify-chain --profile hybrid
    --root ecc-root.cert --aa ecc-aa.cert --ticket ecc-ticket.cert --aid 141)
run_fails("${CERTIFY_PQC}" verify-chain --profile ecc
    --root root.cert --aa aa.cert --ticket ticket.cert --aid 141)
