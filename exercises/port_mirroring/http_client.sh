#!/bin/bash

for i in {1..20000}
do
    curl --silent 10.0.2.2 > /dev/null
    retval=$?
    if [ $retval -ne 0 ]
    then
        echo $retval
        echo 'error when trying to curl. exiting'
        exit 1
    fi
    if [ $(($i % 1000)) -eq 0 ]
    then
        echo -n "$i iteration done\t"
        date
    fi
done
