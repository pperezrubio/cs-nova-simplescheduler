# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Cloud Scaling Simple Scheduler

adds memory oversubscription protection to the Simple Scheduler
"""

from nova import exception
from nova import db
from nova import flags
from nova import utils
from nova.scheduler import driver
from nova.scheduler import simple
from nova.api.ec2 import ec2utils

FLAGS = flags.FLAGS
flags.DEFINE_integer("cs_host_reserved_memory_mb", 0,
                     "memory reserved for base OS")


class SimpleScheduler(simple.SimpleScheduler):
    """Implements Naive Scheduler that tries to find least loaded host without
       oversubscription of memory."""

    #overrides method from driver.Scheduler
    def assert_compute_node_has_enough_memory(self, context,
                                              instance_ref, dest):
        """Checks if destination host has enough memory for live migration.


        :param context: security context
        :param instance_ref: nova.db.sqlalchemy.models.Instance object
        :param dest: destination host

        """

        # Getting total available memory and disk of host
        avail = self._get_compute_info(context, dest, 'memory_mb')

        # Getting total used memory and disk of host
        # It should be sum of memories that are assigned as max value,
        # because overcommiting is risky.
        used = 0
        instance_refs = db.instance_get_all_by_host(context, dest)
        used_list = [i['memory_mb'] for i in instance_refs]
        if used_list:
            used = reduce(lambda x, y: x + y, used_list)

        mem_inst = instance_ref['memory_mb']
        avail = avail - used - FLAGS.cs_host_reserved_memory_mb
        if avail <= mem_inst:
            instance_id = ec2utils.id_to_ec2_id(instance_ref['id'])
            reason = _("Lack of memory(host:%(avail)s"\
                       " <= instance:%(mem_inst)s)"\
                       "on $(dest)")
            raise exception.InsufficientFreeMemory(uuid=dest)

    #overrides method from SimpleScheduler
    def _schedule_instance(self, context, instance_id, *_args, **_kwargs):
        """Picks a host that is up and has the fewest running instances."""
        instance_ref = db.instance_get(context, instance_id)
        if (instance_ref['availability_zone']
            and ':' in instance_ref['availability_zone']
            and context.is_admin):
            zone, _x, host = instance_ref['availability_zone'].partition(':')
            service = db.service_get_by_args(context.elevated(), host,
                                             'nova-compute')
            if not self.service_is_up(service):
                raise driver.WillNotSchedule(_("Host %s is not alive") % host)

            # TODO(vish): this probably belongs in the manager, if we
            #             can generalize this somehow
            self.assert_compute_node_has_enough_memory(context, instance_ref,
                                                      service['host'])
            now = utils.utcnow()
            db.instance_update(context, instance_id, {'host': host,
                                                      'scheduled_at': now})
            return host
        results = db.service_get_all_compute_sorted(context)
        for result in results:
            (service, instance_cores) = result
            if instance_cores + instance_ref['vcpus'] > FLAGS.max_cores:
                raise driver.NoValidHost(_("All hosts have too many cores"))
            try:
                self.assert_compute_node_has_enough_memory(context,
                                                          instance_ref,
                                                          service['host'])
            except exception.InsufficientFreeMemory:
                break
            if self.service_is_up(service):
                # NOTE(vish): this probably belongs in the manager, if we
                #             can generalize this somehow
                now = utils.utcnow()
                db.instance_update(context,
                                   instance_id,
                                   {'host': service['host'],
                                    'scheduled_at': now})
                return service['host']
        raise driver.NoValidHost(_("Scheduler was unable to locate a host"
                                   " for this request. Is the appropriate"
                                   " service running?"))
