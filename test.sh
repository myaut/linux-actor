#!/bin/bash

MODDIR=/pool/leo4-devel/actor/mod2
REPORTDIR=/tmp/report

if [ ! -d $REPORTDIR ]; then
	mkdir $REPORTDIR
fi

function gen_add_helper() 
{
    MODNAME=$1
    MODPATH=$2
    
    SYSPATH=/sys/module/$MODNAME/sections/
    
    TEXTADDR=$(cat $SYSPATH/.text)
    
    echo -n "add-symbol-file $MODPATH $TEXTADDR "
    
    for SECT in $(ls -a $SYSPATH); do
        if [ $SECT == "." -o $SECT == ".." -o $SECT == ".text" -o ${SECT:0:2} == "__" ]; then
            continue
        fi
        
        ADDR=$(cat $SYSPATH/$SECT)
        echo "-s $SECT $ADDR \\"
    done
    
    echo
}

function add_module() {
    MODNAME=$1
    MODFILE=$MODNAME.ko
    MODPATH=$MODDIR/$MODFILE

    if insmod $MODPATH; then
		echo "Added module $MODNAME"
	else
		exit 1
	fi
    
    gen_add_helper $MODNAME $MODPATH
}

function rm_module() {
    MODNAME=$1
    MODFILE=$MODNAME.ko
    MODPATH=$MODDIR/$MODFILE

    if rmmod $MODPATH; then
		echo "Removed module $MODNAME"
	else
		exit 1
	fi
}

function run_tests() {
	TESTNAME=$1
	TESTTIME=10
	
	echo "Testing $TESTNAME..."

	./ctxsw.stp > $REPORTDIR/${TESTNAME}_ctxsw.out &
	
	opcontrol --reset 
	opcontrol --start
	
	echo -n $TESTNAME > /proc/actor_bench
	sleep $TESTTIME
	
	opcontrol --stop
	
	opreport -p $MODDIR -l > $REPORTDIR/${TESTNAME}_oprof.out
}

function enable_debugger() {
	echo "Enabled debugger!"
	
	echo ttyS1,115200 > /sys/module/kgdboc/parameters/kgdboc
}

enable_debugger

add_module actor
add_module bench

read -p "Press [Enter] to start tests... "

run_tests actor
run_tests multi_actor

rm_module bench
rm_module actor
