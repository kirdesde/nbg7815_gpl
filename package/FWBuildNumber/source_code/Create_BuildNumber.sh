#!/bin/sh

if [ -f ./BuildNumber ]; then
	echo "BuildNumber="$(cat BuildNumber)
	exit
fi

BuildNumber=`date +%s`
echo "BuildNumber=$BuildNumber"

echo "$BuildNumber" > ./BuildNumber

exit
