SpaceJava
=========

This is a Java implementation of Space: an end-to-end encrypted, blockchain storage platform.

Setup
=====
Libraries

    mkdir libs
    ln -s <bcjavalib> libs/BCJava.jar
    ln -s <aliasjavalib> libs/AliasJava.jar
    ln -s <financejavalib> libs/FinanceJava.jar
    ln -s <protolib> libs/protobuf-lite-3.0.1.jar

Protocol Buffers

    cd <path/to/Space>
    ./build.sh --javalite_out=<path/to/SpaceJava>/source/

Build
=====

    ./build.sh
