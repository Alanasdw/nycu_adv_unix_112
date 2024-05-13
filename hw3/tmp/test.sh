
workdir=./tmp

len=4
test_commands=( "./sdb" "./sdb ./hello" "./sdb ./guess"  "./sdb ./hello")
test_inputs=./in
test_outputs=./out
test_expected=./exp

for ((i=0; i < len; i++)); do
    ${test_commands[$i]} < $test_inputs$i > $test_outputs$i
    diff $test_outputs$i $test_expected$i > /dev/null
    if [ $? -eq 0 ] ; then
        echo "test$i passed"
    else
        echo "---------------------------------test$i---------------------------------"
        diff $test_outputs$i $test_expected$i
        echo "---------------------------------test$i---------------------------------"
    fi
done

# ./sdb < $workdir/in_ex1
