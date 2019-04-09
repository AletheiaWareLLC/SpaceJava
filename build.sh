#!/bin/bash
#
# Copyright 2019 Aletheia Ware LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

if [ -d out ]; then
    rm -r out
fi
mkdir out

SOURCES=(
    source/com/aletheiaware/space/Space.java
    source/com/aletheiaware/space/SpaceProto.java
    source/com/aletheiaware/space/utils/SpaceUtils.java
)

javac -cp libs/AliasJava.jar:libs/BCJava.jar:libs/FinanceJava.jar:libs/protobuf-lite-3.0.1.jar ${SOURCES[*]} -d out
jar cvf out/SpaceJava.jar -C out .