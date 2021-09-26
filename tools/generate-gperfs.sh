#!/bin/sh

name=$1
prefix=$2

echo "struct ${name}_name { const char* name; int id; };"
echo "%null-strings"
echo "%%"

while read line; do
    echo "$line, ${line}"
done;