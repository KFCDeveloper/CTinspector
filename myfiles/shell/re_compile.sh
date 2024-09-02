#!/bin/bash

cd /home/ydy/projects/CTinspector-master
rm build -rf
mkdir build
cd build
cmake ..
make

cd /home/ydy/projects/CTinspector-master/ebpf_example
rm -f vm_*.o
make