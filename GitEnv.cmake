execute_process(
        COMMAND git log --pretty=format:%h -n 1
        OUTPUT_VARIABLE GIT_HASH
        RESULT_VARIABLE RESULT
        ERROR_QUIET)

if (RESULT EQUAL "0")
    string(STRIP ${GIT_HASH} GIT_HASH)
endif ()

execute_process(
        COMMAND git diff --quiet
        RESULT_VARIABLE RESULT
        ERROR_QUIET)

if (RESULT EQUAL "1")
    set(GIT_DIRTY "-dirty")
endif ()

execute_process(
        COMMAND git rev-list --count HEAD
        OUTPUT_VARIABLE GIT_COMMITS
        RESULT_VARIABLE RESULT
        ERROR_QUIET)

if (RESULT EQUAL "0")
    string(STRIP ${GIT_COMMITS} GIT_COMMITS)
endif ()

string(CONCAT GIT_ENV
        "const char * GIT_HASH = \"${GIT_HASH}\";\n"
        "const char * GIT_DIRTY = \"${GIT_DIRTY}\";\n"
        "const char * GIT_COMMITS = \"${GIT_COMMITS}\";\n"
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/GitEnv.cpp "${GIT_ENV}")
