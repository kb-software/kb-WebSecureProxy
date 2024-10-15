#!/usr/bin/env bash


function m_echo_and_exit() {
    MSG=$1
    EXITCODE=$2
    echo "$MSG" >&2
    exit $EXITCODE
}

function m_compile() {
    for last; do true; done
    FILE=$last
    length=$(($#-1))
    ARGS=${@:1:$length}
    echo "$CC $CFLAGS $ARGS $FILE"
    $CC $CFLAGS $ARGS $FILE || m_echo_and_exit "Error compiling $FILE" 1
}
function m_compile_asm() {
    FILE=$1
    echo "nasm -f elf$BIT -F dwarf -g $FILE"
    nasm -f elf$BIT -F dwarf -g $FILE || m_echo_and_exit "Error compiling $FILE" 2
}
function m_linking() {
    ARGS=$@
    echo "$LC $ARGS"
    $LC $ARGS || m_echo_and_exit "Error linking: $LC $ARGS" 3
}