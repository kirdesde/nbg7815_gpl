#!/bin/sh
# execute this script under "beryl" directory
echo quartz
git log -n 1
cd ..
echo
echo

cd ./quartz/dl/private
for D in `find ./ -maxdepth 1 -type d`
do
        [ $D = "./" ] || {
		echo $D
                cd $D
                git log -n 1
                cd ..
                echo 
                echo 
        }
done

