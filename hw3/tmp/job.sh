#!/bin/bash

# command usage
# ./wait.sh "program_name arg0 arg1 ..." in_file out_file exp_file tmp_file

# command=./sdb
# in=in/in0
# exp=exp/exp0
# out=out/out0
# temp_name=./tmp

command=$1
in=$2
out=$3
exp=$4
temp_name=$5

# echo $command
# echo $in
# echo $out
# echo $exp
# echo $temp_name

rm -f $out
touch $out

while IFS= read -r line; do
    sleep .01
    echo "$line"
done < $in | script -f -c "$command" $temp_name > /dev/null

tr -d '\000' < $temp_name > $out
head --lines=-3 $out > $temp_name
tail -n +2 $temp_name > $out

rm $temp_name


diff -b $out $exp > /dev/null
# echo $?
if [ $? -eq 0 ] ; then
    echo "test $5 passed"
else
    echo "---------------------------------test $5---------------------------------"
    # diff $test_outputs$i $test_expected$i
    diff -b $out $exp
    echo "---------------------------------test $5---------------------------------"
fi
