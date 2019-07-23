SpaceJava
=========

This is a Java implementation of Space - secure, private, storage.

Setup
=====

Protocol Buffers

    cd <path/to/Space>
    ./build.sh --javalite_out=<path/to/SpaceJava>/source/

JAR Libraries

    mkdir libs
    ln -s <awcommonjavalib> libs/AletheiaWareCommonJava.jar
    ln -s <bcjavalib> libs/BCJava.jar
    ln -s <aliasjavalib> libs/AliasJava.jar
    ln -s <financejavalib> libs/FinanceJava.jar
    ln -s <protolib> libs/protobuf-lite-3.0.1.jar

Build
=====

    ./build.sh
