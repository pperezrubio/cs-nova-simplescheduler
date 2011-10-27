Alternate scheduler for use with OpenStack Nova based on 
nova.scheduler.simple.SimpleScheduler that doesn't oversubscribe memory

Currently works on stable/diablo, not on master

`tests.py` should be run as part of the `nova` unittests.

Installing and Using
=====================
Just run `python setup.py install`

In nova.conf set the following flags:

    --scheduler_driver=cloudscaling.nova.scheduler.simple.SimpleScheduler
    --cs_host_reserved_memory_mb=1024


Where `cs_host_reserved_memory_mb` specifies how much memory (
in megabytes) to reserve for the host
