#!/bin/bash

file=./sdb

in=in/in0
exp=exp/exp0
out=out/out0

rm $out

while IFS= read -r line; do
    sleep .01
    echo "$line"
done < $in | script -f -c $file ./tmp > /dev/null

tr -d '\000' < ./tmp > $out
head --lines=-3 $out > ./tmp
tail -n +2 ./tmp > $out
