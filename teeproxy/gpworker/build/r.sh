#!bin/bash

pkill gpworker
cp -r gpworker /vendor/bin/gpworker
rm -f *.log

parallel -j 128 --ungroup /vendor/bin/gpworker gpworker{} ::: {0..127}
