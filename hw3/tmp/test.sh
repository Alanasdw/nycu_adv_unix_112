
workdir=./tmp

len=4
test_commands=( "./sdb" "./sdb ./hello" "./sdb ./guess"  "./sdb ./hello")
test_inputs=./in/in
test_outputs=./out/out
test_expected=./exp/exp

rm -r out
mkdir out
for ((i=0; i < len; i++)); do
    ./job.sh "${test_commands[$i]}" $test_inputs$i $test_outputs$i $test_expected$i $i
done

# ./sdb < $workdir/in_ex1
