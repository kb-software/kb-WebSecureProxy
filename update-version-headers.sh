#!/usr/bin/env bash

#####################################################################
#                                                                   #
# Update the revision number in all SDH version header files.       #
#                                                                   #
#####################################################################

echo "$0"

SYSTEM=$(uname -s)
# SDH version variables in sdh-version headers
REGEX_OLD_VERSION="SDH_VERSION_4_NO\|WS_VERSION_4_NO"

if svn info > /dev/null; then
    # cut with delimiter " ", second field
    NEW_VERSION=$(svn info | grep Revision | cut -d " " -f 2)
elif git status > /dev/null; then
    NEW_VERSION=$(git log | grep git-svn-id | sed 's/.*git-svn-id:.*\(trunk@[0-9]*\) .*/\1/g' | cut -c 7- | sort | tail -n1)
fi

if [ -n "$NEW_VERSION" ] ;
then
    echo "Writing revision number $NEW_VERSION into SDH version header files."
else
    echo "Could not find new revision number"
    exit 1
fi

# for some reason too slow, gives also the information about the range and whether the revision was modified
#NEWVERSION = $(svnversion)

# grep recursively and list only names of files containing the $REGEX_OLD_VERSION
case "$SYSTEM" in
    Linux)  grep -rl src/ -e $REGEX_OLD_VERSION --include="*.h" | xargs sed -ri "s/[0-9]{4}/$NEW_VERSION/g"
	;;
    FreeBSD) grep -rl src/ -e $REGEX_OLD_VERSION --include="*.h" | xargs sed -ri "" "s/[0-9]{4}/$NEW_VERSION/g"
	;;
esac	
echo "$0 Success"
