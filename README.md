Alternate scheduler for use with OpenStack Nova based on nova.scheduler.simple.SimpleScheduler that doesn't oversubscribe memory

The SimpleScheduler massively oversubscribes memory without regard. The check in Diablo doesn't work with libvirt/kvm, this fixes the bug.  It is a simple and straight-forward, iterative fix.  There is a better solution being introduced in Essex, currently in review.

This should be used by anyone using libvirt/kvm and the SimpleScheduler on OpenStack Nova (Diablo).

`tests.py` should be run as part of the `nova` unittests.

Installing and Using
=====================
Just run `python setup.py install`

In nova.conf set the following flags:

    --scheduler_driver=cloudscaling.nova.scheduler.simple.SimpleScheduler
    --cs_host_reserved_memory_mb=1024


Where `cs_host_reserved_memory_mb` specifies how much memory (
in megabytes) to reserve for the host
