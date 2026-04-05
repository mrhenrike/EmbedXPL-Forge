#!/bin/bash

COUNTER=900000000
until [ $COUNTER -lt 10 ]; do
rm -rf netgear.txt
zmap -p23 -w ranges.txt -o netgear.txt
python netgear.py netgear.txt
pkill -9 python
done
