# cmake -P script: run the SBOM driver with SOURCE_DATE_EPOCH set at
# build time.
#
# Keep a value that is already in the environment. When it is empty, use
# the last commit time of the enclosing checkout when SBOM_ROOT holds
# files tracked there. A tarball unpacked into an untracked directory of
# another checkout does not take that checkout's time. A tree with no git
# leaves the variable empty, and gen-sbom uses its own default.
#
# Arguments after "--" are the driver command.

if(NOT DEFINED SBOM_ROOT)
    set(SBOM_ROOT "")
endif()

set(_sde "$ENV{SOURCE_DATE_EPOCH}")
if(_sde STREQUAL "" AND NOT SBOM_ROOT STREQUAL "")
    find_program(_wolfssl_compliance_tooling_git git)
    if(_wolfssl_compliance_tooling_git)
        set(_sde "")
        execute_process(
            COMMAND "${_wolfssl_compliance_tooling_git}" -C "${SBOM_ROOT}"
                    ls-files --error-unmatch -- .
            OUTPUT_QUIET
            ERROR_QUIET
            RESULT_VARIABLE _git_rc)
        if(_git_rc EQUAL 0)
            execute_process(
                COMMAND "${_wolfssl_compliance_tooling_git}" -C "${SBOM_ROOT}"
                        log -1 --format=%ct
                OUTPUT_VARIABLE _sde
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE _git_rc)
            if(NOT _git_rc EQUAL 0)
                set(_sde "")
            endif()
        endif()
        if(NOT _sde STREQUAL "")
            set(ENV{SOURCE_DATE_EPOCH} "${_sde}")
        endif()
    endif()
endif()

math(EXPR _last "${CMAKE_ARGC} - 1")
set(_args "")
set(_seen_dd FALSE)
foreach(_i RANGE 0 ${_last})
    set(_a "${CMAKE_ARGV${_i}}")
    if(_seen_dd)
        # A raw semicolon would split the CMake list and break the argument.
        string(REPLACE ";" "\\;" _safe "${_a}")
        list(APPEND _args "${_safe}")
    elseif(_a STREQUAL "--")
        set(_seen_dd TRUE)
    endif()
endforeach()

if(NOT _args)
    message(FATAL_ERROR "sbom-with-sde.cmake: no command after --")
endif()

execute_process(COMMAND ${_args} RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "SBOM generation failed (${_rc})")
endif()
