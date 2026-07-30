#! /usr/bin/env bash

validate_input()
{
    local name="$1"
    local value="$2"
    local pattern="$3"
    if [[ ! "${value}" =~ ${pattern} ]]
    then
        echo "FATAL: invalid value for ${name}: '${value}'" >&2
        exit 101
    fi
}

validate_inputs()
{
    # Validate each input against an allowlist pattern. Fails with an error if
    # the value contains characters outside the expected set.

    # bool: true or false (empty is also accepted for optional inputs)
    validate_input "verbose"          "${VERBOSE}"          '^(true|false)$'
    validate_input "concise"          "${CONCISE}"          '^(true|false)$'

    # path: alphanumeric plus / . _ - (empty accepted for optional inputs)
    validate_input "scan-path"        "${SCAN_PATH}"        '^[a-zA-Z0-9_.\/\-]+$'
    [[ -n "${SCAN_PROFILE}" ]]       && validate_input "scan-profile"     "${SCAN_PROFILE}"     '^[a-zA-Z0-9_.\/\-]+$'
    [[ -n "${REPORT}" ]]             && validate_input "report"           "${REPORT}"           '^[a-zA-Z0-9_.\/\-]+$'
    [[ -n "${LOG_FILE}" ]]           && validate_input "log-file"         "${LOG_FILE}"         '^[a-zA-Z0-9_.\/\-]+$'
    [[ -n "${CA_PATH}" ]]            && validate_input "ca-path"          "${CA_PATH}"          '^[a-zA-Z0-9_.\/\-]+$'

    # string: csv of alpha keywords (develop, release, optional, transitive)
    [[ -n "${CHECK_DEPS}" ]]         && validate_input "check-deps"       "${CHECK_DEPS}"       '^[a-zA-Z]+(,[a-zA-Z]+)*$'

    # integer
    [[ -n "${TRANSITIVE_DEPTH}" ]]   && validate_input "transitive-depth" "${TRANSITIVE_DEPTH}" '^[0-9]+$'

    # artifact selection: keyword with an optional :version floor
    [[ -n "${TARGET_PYTHON}" ]]      && validate_input "target-python"    "${TARGET_PYTHON}"    '^[0-9]+(\.[0-9]+)*$'
    [[ -n "${TARGET_OS}" ]]          && validate_input "target-os"        "${TARGET_OS}"        '^(linux|macos|windows)(:[0-9]+(\.[0-9]+)*)?$'
    [[ -n "${TARGET_ARCH}" ]]        && validate_input "target-arch"      "${TARGET_ARCH}"      '^(x86_64|x86|arm64)$'
    [[ -n "${TARGET_LIBC}" ]]        && validate_input "target-libc"      "${TARGET_LIBC}"      '^(glibc|musl|none)(:[0-9]+(\.[0-9]+)*)?$'
    [[ -n "${TARGET_IMPLEMENTATION}" ]] && validate_input "target-implementation" "${TARGET_IMPLEMENTATION}" '^(cp|pp|jy|ip|py)$'

    # artifact selection: csv of platform tags or presets, and of abi tags
    # whitespace around the separators is tolerated and stripped before use
    [[ -n "${TARGET_PLATFORM}" ]]    && validate_input "target-platform"  "${TARGET_PLATFORM}"  '^[[:space:]]*[a-zA-Z0-9_.\-]+([[:space:]]*,[[:space:]]*[a-zA-Z0-9_.\-]+)*[[:space:]]*$'
    [[ -n "${TARGET_ABI}" ]]         && validate_input "target-abi"       "${TARGET_ABI}"       '^[[:space:]]*[a-zA-Z0-9_]+([[:space:]]*,[[:space:]]*[a-zA-Z0-9_]+)*[[:space:]]*$'

    # string: alpha keyword only (pass, warn, fail)
    [[ -n "${LOG_LEVEL}" ]]          && validate_input "log-level"        "${LOG_LEVEL}"        '^[a-zA-Z]+$'

    # string: printable label, no shell metacharacters
    [[ -n "${LOG_LABEL}" ]]          && validate_input "log-label"        "${LOG_LABEL}"        '^[a-zA-Z0-9_ \-]+$'

    # Portal organization and group: alphanumeric plus spaces, - and _
    # RL_TOKEN is not validated here; Community tokens have prefix rlcmm, Portal tokens have prefix rls3c
    [[ -n "${RL_ORG}" ]]             && validate_input "rl-org"           "${RL_ORG}"           '^[a-zA-Z0-9_ \-]+$'
    [[ -n "${RL_GROUP}" ]]           && validate_input "rl-group"         "${RL_GROUP}"         '^[a-zA-Z0-9_ \-]+$'

    # server: DNS name or IP address (alphanumeric plus . : / -)
    [[ -n "${RL_SERVER}" ]]          && validate_input "rl-server"        "${RL_SERVER}"        '^[a-zA-Z0-9_.\/:\-]+$'

    # proxy
    [[ -n "${PROXY_SERVER}" ]]       && validate_input "proxy-server"     "${PROXY_SERVER}"     '^[a-zA-Z0-9_.\-]+$'
    [[ -n "${PROXY_PORT}" ]]         && validate_input "proxy-port"       "${PROXY_PORT}"       '^[0-9]+$'
    [[ -n "${PROXY_USER}" ]]         && validate_input "proxy-user"       "${PROXY_USER}"       '^[a-zA-Z0-9_.@\-]+$'
    # PROXY_PASSWORD is not validated: passwords may contain any printable character
}

validate_proxy()
{
    # proxy-port is required when proxy-server is specified
    if [ "${PROXY_SERVER}" != "" ]
    then
        if [ "${PROXY_PORT}" == "" ]
        then
            echo "FATAL: when specifying a proxy server you also must specify a proxy port"
            exit 101
        fi
    fi

    # proxy-password and proxy-server are required when proxy-user is specified
    if [ "${PROXY_USER}" != "" ]
    then
        if [ "${PROXY_PASSWORD}" == "" ]
        then
            echo "FATAL: when specifying a proxy user you also must specify a proxy password"
            exit 101
        fi
        if [ "${PROXY_SERVER}" == "" ]
        then
            echo "FATAL: when specifying a proxy user you must also specify a server and port"
            exit 101
        fi
    fi
}

validate_artifact_selection()
{
    # Artifact selection currently applies to PyPI packages only.
    # rl-protect enforces these same rules; catching them here gives a clearer
    # error before we spend time installing the tool and contacting the API.

    # target-python enables selection: it is required by any other target option
    if [ "${TARGET_PYTHON}" == "" ]
    then
        local opt
        for opt in TARGET_OS TARGET_ARCH TARGET_LIBC TARGET_PLATFORM TARGET_IMPLEMENTATION TARGET_ABI
        do
            if [ "${!opt}" != "" ]
            then
                echo "FATAL: target-python is required when selecting artifacts" >&2
                exit 101
            fi
        done
        return
    fi

    # os and arch describe one platform together; neither is usable on its own
    if [ "${TARGET_OS}" != "" ] && [ "${TARGET_ARCH}" == "" ]
    then
        echo "FATAL: when specifying target-os you must also specify target-arch" >&2
        exit 101
    fi
    if [ "${TARGET_ARCH}" != "" ] && [ "${TARGET_OS}" == "" ]
    then
        echo "FATAL: when specifying target-arch you must also specify target-os" >&2
        exit 101
    fi

    # libc refines the os/arch pair, so it cannot stand on its own either
    if [ "${TARGET_LIBC}" != "" ] && [ "${TARGET_OS}" == "" ]
    then
        echo "FATAL: when specifying target-libc you must also specify target-os and target-arch" >&2
        exit 101
    fi

    # target-platform and target-os/arch are two ways to say the same thing:
    # rl-protect takes their union, which widens selection more than intended
    if [ "${TARGET_PLATFORM}" != "" ] && [ "${TARGET_OS}" != "" ]
    then
        echo "WARNING: target-platform and target-os/target-arch are combined as a union by rl-protect;" >&2
        echo "WARNING: specify only one of them to target a single platform" >&2
    fi
}

validate_access()
{
    validate_proxy
    validate_artifact_selection

    if [ "${RL_TOKEN}" == "" ]
    then
        echo "FATAL: RL_TOKEN is required" >&2
        exit 101
    fi

    TOKEN_TYPE=""
    if [[ "${RL_TOKEN}" =~ ^rls3c.* ]]
    then
        TOKEN_TYPE="PORTAL"
    fi
    if [[ "${RL_TOKEN}" =~ ^rlcmm.* ]]
    then
        TOKEN_TYPE="COMMUNITY"
    fi

    if [ "${TOKEN_TYPE}" == "PORTAL" ]
    then
        if [ "${RL_SERVER}" == "" ]
        then
            echo "FATAL: rl-server is required for Portal tokens" >&2
            exit 101
        fi
        if [ "${RL_ORG}" == "" ]
        then
            echo "FATAL: rl-org is required for Portal tokens" >&2
            exit 101
        fi
    fi
}

install_tool()
{
    # no python venv needed in gh-action

    pip --quiet \
        --disable-pip-version-check \
        --no-color \
        install rl-protect 2>2 1>1
    RESULT=$?

    cat 1
    if [ "${RESULT}" != "0" ]
    then
        cat 2
        echo "Fatal: cannot install rl-protect" >&2
        exit 101
    fi
    unset RESULT

    rl-protect --version
}

show_params()
{
    if [ "${VERBOSE}" != "true" ]
    then
        return
    fi

    cat <<!
Params:
    SCAN_PATH:        ${SCAN_PATH}
    SCAN_PROFILE:     ${SCAN_PROFILE}
    CHECK_DEPS:       ${CHECK_DEPS}
    TRANSITIVE_DEPTH: ${TRANSITIVE_DEPTH}
    REPORT:           ${REPORT}

    TARGET_PYTHON:         ${TARGET_PYTHON}
    TARGET_OS:             ${TARGET_OS}
    TARGET_ARCH:           ${TARGET_ARCH}
    TARGET_LIBC:           ${TARGET_LIBC}
    TARGET_PLATFORM:       ${TARGET_PLATFORM}
    TARGET_IMPLEMENTATION: ${TARGET_IMPLEMENTATION}
    TARGET_ABI:            ${TARGET_ABI}

    LOG_FILE:         ${LOG_FILE}
    LOG_LEVEL:        ${LOG_LEVEL}
    LOG_LABEL:        ${LOG_LABEL}

    TOKEN_TYPE:       ${TOKEN_TYPE}
    RL_SERVER:        ${RL_SERVER}
    RL_ORG:           ${RL_ORG}
    RL_GROUP:         ${RL_GROUP}

    PROXY_SERVER:     ${PROXY_SERVER}
    PROXY_PORT:       ${PROXY_PORT}
    PROXY_USER:       ${PROXY_USER}
    CA_PATH:          ${CA_PATH}

    CONCISE:          ${CONCISE}
    VERBOSE:          ${VERBOSE}
!
}

run_scan()
{
    local Params=( )

    # what are we scanning
    if [ "${SCAN_PATH}" != "" ]
    then
        Params+=( --scan-path="${SCAN_PATH}" )
    fi
    if [ "${SCAN_PROFILE}" != "" ]
    then
        Params+=( --scan-profile="${SCAN_PROFILE}" )
    fi

    # auth and portal params -------------
    if [ "${RL_SERVER}" != "" ]
    then
        Params+=( --rl-server="${RL_SERVER}" )
    fi
    if [ "${RL_TOKEN}" != "" ]
    then
        Params+=( --rl-token="${RL_TOKEN}" )
    fi
    if [ "${RL_ORG}" != "" ]
    then
        Params+=( --rl-org="${RL_ORG}" )
    fi
    if [ "${RL_GROUP}" != "" ]
    then
        Params+=( --rl-group="${RL_GROUP}" )
    fi
    if [ "${REPORT}" != "" ]
    then
        Params+=( --report="${REPORT}" )
    fi

    # log -------------------------------
    if [ "${LOG_FILE}" != "" ]
    then
        Params+=( --log-file="${LOG_FILE}" )
        if [ "${LOG_LEVEL}" != "" ]
        then
            Params+=( --log-level="${LOG_LEVEL}" )
        fi
        if [ "${LOG_LABEL}" != "" ]
        then
            Params+=( --log-label="${LOG_LABEL}" )
        fi
    fi

    if [ "${CHECK_DEPS}" != "" ]
    then
        Params+=( --check-deps="${CHECK_DEPS}" )
    fi
    if [ "${TRANSITIVE_DEPTH}" != "" ]
    then
        # transitive-depths is only valid when we ask for transitive
        if [[ "${CHECK_DEPS}" == *"transitive"* ]]
        then
            Params+=( --transitive-depth="${TRANSITIVE_DEPTH}" )
        fi
    fi
    # artifact selection ----------------
    # nothing is passed unless target-python is set; it is what enables selection
    if [ "${TARGET_PYTHON}" != "" ]
    then
        Params+=( --target-python="${TARGET_PYTHON}" )

        if [ "${TARGET_OS}" != "" ]
        then
            Params+=( --target-os="${TARGET_OS}" )
        fi
        if [ "${TARGET_ARCH}" != "" ]
        then
            Params+=( --target-arch="${TARGET_ARCH}" )
        fi
        if [ "${TARGET_LIBC}" != "" ]
        then
            Params+=( --target-libc="${TARGET_LIBC}" )
        fi
        if [ "${TARGET_IMPLEMENTATION}" != "" ]
        then
            Params+=( --target-implementation="${TARGET_IMPLEMENTATION}" )
        fi

        # repeatable options: expand our csv input into one flag per value
        # validate_inputs has already restricted these to the csv separator
        # plus optional whitespace, so word splitting on the comma is safe here
        local value
        if [ "${TARGET_PLATFORM}" != "" ]
        then
            for value in ${TARGET_PLATFORM//,/ }
            do
                Params+=( --target-platform="${value}" )
            done
        fi
        if [ "${TARGET_ABI}" != "" ]
        then
            for value in ${TARGET_ABI//,/ }
            do
                Params+=( --target-abi="${value}" )
            done
        fi
    fi

    if [ "${CONCISE}" == "true" ]
    then
        Params+=( --concise )
    fi

    # ------------------------------------
    # always
    Params+=( --fail-only )
    Params+=( --no-tracking )
    Params+=( --no-color )
    Params+=( --return-status ) # will force exit 0 on pass and exit 1 on fail/error

    # ------------------------------------
    # proxy
    if [ "${PROXY_SERVER}" != "" ]
    then
        Params+=( --proxy-server="${PROXY_SERVER}" )
    fi
    if [ "${PROXY_PORT}" != "" ]
    then
        Params+=( --proxy-port="${PROXY_PORT}" )
    fi
    if [ "${PROXY_USER}" != "" ]
    then
        Params+=( --proxy-user="${PROXY_USER}" )
    fi
    if [ "${PROXY_PASSWORD}" != "" ]
    then
        Params+=( --proxy-password="${PROXY_PASSWORD}" )
    fi

    # ------------------------------------
    if [ "${CA_PATH}" != "" ]
    then
        Params+=( --ca-path="${CA_PATH}" )
    fi

    rl-protect scan "${Params[@]}" 2>2 >1
    RESULT=$?

    cat 1 # always show stdout

    if [ "${RESULT}" != "0" ]
    then
        echo "RESULT: ${RESULT}"
        echo "Stderr:"
        cat 2 # on error or fail show stderr also
    fi

    # use the RESULT
    # to set the OUT_STATUS and the OUT_DESCRIPTION
    local pre="rl-protect scan produced"
    if [ "${RESULT}" == "0" ]
    then
        OUT_DESCRIPTION="${pre} PASS"
        OUT_STATUS="pass"
    else
        OUT_DESCRIPTION="${pre} FAIL"
        OUT_STATUS="fail"
    fi
}

set_output()
{
    echo "description=${OUT_DESCRIPTION}" >> $GITHUB_OUTPUT
    echo "status=${OUT_STATUS}"           >> $GITHUB_OUTPUT
}

main()
{
    validate_inputs  # exit 101 on invalid input
    validate_access
    show_params      # only if verbose
    install_tool
    run_scan
    set_output
}

main
