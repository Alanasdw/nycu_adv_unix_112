
workdir=./tmp

len=4
test_commands=( "./sdb" "./sdb ./hello" "./sdb ./guess"  "./sdb ./hello")
test_inputs=./in/in
test_outputs=./out/out
test_expected=./exp/exp

rm -r out
mkdir out
for ((i=0; i < len; i++)); do
    # touch .tmp
    # ${test_commands[$i]} < $test_inputs$i > .tmp
    # tr -d '\000' < .tmp > $test_outputs$i
    # rm .tmp

    while IFS= read -r line; do
        sleep .01
        echo "$line"
    done < $test_inputs$i | script -f -c "${test_commands[$i]}" ./tmp > /dev/null

    tr -d '\000' < ./tmp > $test_outputs$i
    head --lines=-3 $test_outputs$i > ./tmp
    tail -n +2 ./tmp > $test_outputs$i
    rm ./tmp

    diff --strip-trailing-cr $test_outputs$i $test_expected$i > /dev/null
    # echo $?
    if [ $? -eq 0 ] ; then
        echo "test$i passed"
    else
        echo "---------------------------------test$i---------------------------------"
        # diff $test_outputs$i $test_expected$i
        diff -y <(cat $test_outputs$i) <(cat $test_expected$i)
        echo "---------------------------------test$i---------------------------------"
    fi
done

# ./sdb < $workdir/in_ex1
