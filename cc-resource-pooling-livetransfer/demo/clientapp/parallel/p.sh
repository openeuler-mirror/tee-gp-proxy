# ! /bin/bash

# set maximal number of parallel jobs
MAX_NUM_LCOUNT=100
MAX_NUM_CCA=9
# END_NUM=$(($MAX_NUM_CCA-1))
END_NUM=$MAX_NUM_CCA

if true; then
for ((LCOUNT = 0; LCOUNT < $MAX_NUM_LCOUNT; LCOUNT++))
do
   echo -e "\n"remove {}_$LCOUNT.log ::: $(eval echo "{1..$END_NUM}") 
   parallel -j $MAX_NUM_CCA rm "-f" {}_$LCOUNT.log ::: $(eval echo "{1..$END_NUM}") 
   parallel -j $MAX_NUM_CCA --ungroup bash ../testcase{}/build/test.sh "| tee" {}_$LCOUNT.log ::: $(eval echo "{1..$END_NUM}") 
   # parallel -j $MAX_NUM_CCA --ungroup ../testcase0/build/testcase "| tee" {}_$LCOUNT.log ::: $(eval echo "{0..$END_NUM}") 
done	
fi
