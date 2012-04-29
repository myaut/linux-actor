#!/bin/bash

MODDIR=/pool/leo4-devel/actor/mod2

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
    
    insmod $MODPATH
    
    gen_add_helper $MODNAME $MODPATH
}
    
add_module actor
add_module bench

echo ttyS1,115200 > /sys/module/kgdboc/parameters/kgdboc

echo -n 'pp_thread' > /proc/actor_bench

