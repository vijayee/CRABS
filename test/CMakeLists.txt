if (BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    project(testcrabs C CXX)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)

    add_executable(testcrabs
        test_main.cpp
        test_refcounter.cpp
        test_state_machine.cpp
        test_crdt.cpp
    )

    add_dependencies(testcrabs crabs)
    target_link_libraries(testcrabs PRIVATE crabs)
    target_link_libraries(testcrabs PRIVATE GTest::gtest_main)
    target_link_libraries(testcrabs PRIVATE GTest::gmock)

    include(GoogleTest)
    gtest_discover_tests(testcrabs)
endif()
