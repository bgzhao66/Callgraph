#!/bin/sh
# Embed a binary file as a C array: embed_bpf.sh INPUT OUTPUT SYMBOL
set -eu

input=$1
output=$2
name=$3

{
    printf '#pragma once\n'
    printf 'static const unsigned char %s[] = {\n' "$name"
    od -An -v -tu1 "$input" | tr -s ' ' ',' | sed 's/^,//; s/$/,/'
    printf '};\n'
    printf 'static const unsigned int %s_len = %s;\n' "$name" "$(wc -c < "$input")"
} > "$output"
