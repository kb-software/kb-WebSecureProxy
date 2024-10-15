#!/usr/bin/env bash

if [[ ! $OS_TYPE ]]; then
	echo "OS_TYPE must be set before" 1>&2
	exit 1
fi

if [[ ! $ARCH_TYPE ]]; then
	echo "ARCH_TYPE must be set before" 1>&2
	exit 2
fi


if [[ $OS_TYPE == "LINUX" ]]; then
	if [[ $ARCH_TYPE == "X86" ]]; then
		PF=LinX86
	elif [[ $ARCH_TYPE == "X64" ]]; then
		PF=LinX64
	fi
elif [[ $OS_TYPE == "FREEBSD" ]]; then
	if [[ $ARCH_TYPE == "X86" ]]; then
		echo "$OS_TYPE $ARCH_TYPE unsupported. aborting" 1>&2
		exit 4
	elif [[ $ARCH_TYPE == "X64" ]]; then
		PF=BsdX64
	fi
fi

if [[ ! $PF ]]; then
	echo "$OS_TYPE $ARCH_TYPE not supported by wrapper. Please update script!" 1>&2
	exit 3
fi

$MAKE PLATFORM=$PF