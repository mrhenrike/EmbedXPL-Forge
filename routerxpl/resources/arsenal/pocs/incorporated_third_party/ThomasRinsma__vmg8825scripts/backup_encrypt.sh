#!/usr/bin/env sh
IN="$1"
OUT="$2"
PW="ROOT_PASS_HERE"

openssl enc -e -des3 -md md5 -pass pass:$PW -in "$IN" -out "$OUT"
