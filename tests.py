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
Tests For Cloudscaling Simple Scheduler
"""

import datetime
import mox
import stubout

from novaclient import v1_1 as novaclient
from novaclient import exceptions as novaclient_exceptions

from mox import IgnoreArg
from nova import context
from nova import db
from nova import exception
from nova import flags
from nova import service
from nova import test
from nova import rpc
from nova import utils
from nova.scheduler import api
from nova.scheduler import driver
from nova.scheduler import manager
from nova.scheduler import multi
from nova.compute import power_state
from nova.compute import vm_states

from cloudscaling.nova.scheduler.simple import SimpleScheduler

FLAGS = flags.FLAGS
flags.DECLARE('max_cores', 'cloudscaling.nova.scheduler.simple')
flags.DECLARE('stub_network', 'nova.compute.manager')
flags.DECLARE('instances_path', 'nova.compute.manager')


FAKE_UUID_NOT_FOUND = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
FAKE_UUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'


def _create_instance_dict(**kwargs):
    """Create a dictionary for a test instance"""
    inst = {}
    # NOTE(jk0): If an integer is passed as the image_ref, the image
    # service will use the default image service (in this case, the fake).
    inst['image_ref'] = '1'
    inst['reservation_id'] = 'r-fakeres'
    inst['user_id'] = kwargs.get('user_id', 'admin')
    inst['project_id'] = kwargs.get('project_id', 'fake')
    inst['instance_type_id'] = '1'
    inst['host'] = kwargs.get('host', 'dummy')
    inst['vcpus'] = kwargs.get('vcpus', 1)
    inst['memory_mb'] = kwargs.get('memory_mb', 20)
    inst['local_gb'] = kwargs.get('local_gb', 30)
    inst['vm_state'] = kwargs.get('vm_state', vm_states.ACTIVE)
    inst['power_state'] = kwargs.get('power_state', power_state.RUNNING)
    inst['task_state'] = kwargs.get('task_state', None)
    inst['availability_zone'] = kwargs.get('availability_zone', None)
    inst['ami_launch_index'] = 0
    inst['launched_on'] = kwargs.get('launched_on', 'dummy')
    return inst


def _create_instance(**kwargs):
    """Create a test instance"""
    ctxt = context.get_admin_context()
    return db.instance_create(ctxt, _create_instance_dict(**kwargs))['id']


def _create_request_spec(**kwargs):
    return dict(instance_properties=_create_instance_dict(**kwargs))


class CSSimpleDriverTestCase(test.TestCase):
    """Test case for Cloudscaling simple driver"""
    def setUp(self):
        super(CSSimpleDriverTestCase, self).setUp()
        self.flags(connection_type='fake',
                   stub_network=True,
                   max_cores=4,
                   max_gigabytes=4,
                   network_manager='nova.network.manager.FlatManager',
                   volume_driver='nova.volume.driver.FakeISCSIDriver',
                   scheduler_driver='cloudscaling.nova.scheduler'\
                       '.simple.SimpleScheduler')
        self.scheduler = manager.SchedulerManager()
        self.context = context.get_admin_context()
        self.user_id = 'fake'
        self.project_id = 'fake'
        self._create_instance = _create_instance

    def _create_volume(self):
        """Create a test volume"""
        vol = {}
        vol['size'] = 1
        vol['availability_zone'] = 'test'
        return db.volume_create(self.context, vol)['id']

    def _create_compute_service(self, **kwargs):
        """Create a compute service."""

        dic = {'binary': 'nova-compute', 'topic': 'compute',
               'report_count': 0, 'availability_zone': 'dummyzone'}
        dic['host'] = kwargs.get('host', 'dummy')
        s_ref = db.service_create(self.context, dic)
        if 'created_at' in kwargs.keys() or 'updated_at' in kwargs.keys():
            t = utils.utcnow() - datetime.timedelta(0)
            dic['created_at'] = kwargs.get('created_at', t)
            dic['updated_at'] = kwargs.get('updated_at', t)
            db.service_update(self.context, s_ref['id'], dic)

        dic = {'service_id': s_ref['id'],
               'vcpus': 16, 'memory_mb': 32, 'local_gb': 100,
               'vcpus_used': 16, 'local_gb_used': 10,
               'hypervisor_type': 'qemu', 'hypervisor_version': 12003,
               'cpu_info': ''}
        dic['memory_mb_used'] = kwargs.get('memory_mb_used', 32)
        dic['hypervisor_type'] = kwargs.get('hypervisor_type', 'qemu')
        dic['hypervisor_version'] = kwargs.get('hypervisor_version', 12003)
        db.compute_node_create(self.context, dic)
        return db.service_get(self.context, s_ref['id'])

    def test_regular_user_can_schedule(self):
        """Ensures a non-admin can run an instance"""

        s_ref = self._create_compute_service(host='host1')
        instance_id = self._create_instance()
        ctxt = context.RequestContext('fake', 'fake', False)
        self.scheduler.driver.schedule_run_instance(ctxt, instance_id)
        db.instance_destroy(self.context, s_ref['id'])

    def test_doesnt_report_disabled_hosts_as_up_no_queue(self):
        """Ensures driver doesn't find hosts before they are enabled"""
        # NOTE(vish): constructing service without create method
        #             because we are going to use it without queue
        compute1 = service.Service('host1',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute1.start()
        compute2 = service.Service('host2',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute2.start()
        s1 = db.service_get_by_args(self.context, 'host1', 'nova-compute')
        s2 = db.service_get_by_args(self.context, 'host2', 'nova-compute')
        db.service_update(self.context, s1['id'], {'disabled': True})
        db.service_update(self.context, s2['id'], {'disabled': True})
        hosts = self.scheduler.driver.hosts_up(self.context, 'compute')
        self.assertEqual(0, len(hosts))
        compute1.kill()
        compute2.kill()

    def test_reports_enabled_hosts_as_up_no_queue(self):
        """Ensures driver can find the hosts that are up"""
        # NOTE(vish): constructing service without create method
        #             because we are going to use it without queue
        compute1 = service.Service('host1',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute1.start()
        compute2 = service.Service('host2',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute2.start()
        hosts = self.scheduler.driver.hosts_up(self.context, 'compute')
        self.assertEqual(2, len(hosts))
        compute1.kill()
        compute2.kill()

    def test_least_busy_host_gets_instance_no_queue(self):
        """Ensures the host with less cores gets the next one"""
        s_ref = self._create_compute_service(host='host1')
        s_ref2 = self._create_compute_service(host='host2')
        instance_id1 = self._create_instance(host='host1')
        instance_id2 = self._create_instance()
        host = self.scheduler.driver.schedule_run_instance(self.context,
                                                           instance_id2)
        self.assertEqual(host, 'host2')
        db.instance_destroy(self.context, instance_id2)
        db.instance_destroy(self.context, instance_id1)
        db.instance_destroy(self.context, s_ref['id'])
        db.instance_destroy(self.context, s_ref2['id'])

    def test_specific_host_gets_instance_no_queue(self):
        """Ensures if you set availability_zone it launches on that zone"""
        s_ref = self._create_compute_service(host='host1')
        s_ref2 = self._create_compute_service(host='host2')
        instance_id1 = self._create_instance(host='host1', memory_mb='2')

        instance_id2 = self._create_instance(availability_zone='nova:host1')
        host = self.scheduler.driver.schedule_run_instance(self.context,
                                                           instance_id2)
        self.assertEqual('host1', host)
        db.instance_destroy(self.context, instance_id1)
        db.instance_destroy(self.context, instance_id2)
        db.service_destroy(self.context, s_ref['id'])
        db.service_destroy(self.context, s_ref2['id'])

    def test_wont_schedule_if_specified_host_is_down_no_queue(self):
        compute1 = service.Service('host1',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute1.start()
        s1 = db.service_get_by_args(self.context, 'host1', 'nova-compute')
        now = utils.utcnow()
        delta = datetime.timedelta(seconds=FLAGS.service_down_time * 2)
        past = now - delta
        db.service_update(self.context, s1['id'], {'updated_at': past})
        instance_id2 = self._create_instance(availability_zone='nova:host1')
        self.assertRaises(driver.WillNotSchedule,
                          self.scheduler.driver.schedule_run_instance,
                          self.context,
                          instance_id2)
        db.instance_destroy(self.context, instance_id2)
        compute1.kill()

    def test_will_schedule_on_disabled_host_if_specified_no_queue(self):
        s_ref = self._create_compute_service(host='host1')
        s1 = db.service_get_by_args(self.context, 'host1', 'nova-compute')
        db.service_update(self.context, s1['id'], {'disabled': True})
        instance_id2 = self._create_instance(availability_zone='nova:host1')
        host = self.scheduler.driver.schedule_run_instance(self.context,
                                                           instance_id2)
        self.assertEqual('host1', host)
        db.instance_destroy(self.context, instance_id2)
        db.service_destroy(self.context, s_ref['id'])

    def test_too_many_cores_no_queue(self):
        """Ensures we don't go over max cores"""
        compute1 = service.Service('host1',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute1.start()
        compute2 = service.Service('host2',
                                   'nova-compute',
                                   'compute',
                                   FLAGS.compute_manager)
        compute2.start()
        instance_ids1 = []
        instance_ids2 = []
        for index in xrange(FLAGS.max_cores):
            instance_id = self._create_instance()
            compute1.run_instance(self.context, instance_id)
            instance_ids1.append(instance_id)
            instance_id = self._create_instance()
            compute2.run_instance(self.context, instance_id)
            instance_ids2.append(instance_id)
        instance_id = self._create_instance()
        self.assertRaises(driver.NoValidHost,
                          self.scheduler.driver.schedule_run_instance,
                          self.context,
                          instance_id)
        for instance_id in instance_ids1:
            compute1.terminate_instance(self.context, instance_id)
        for instance_id in instance_ids2:
            compute2.terminate_instance(self.context, instance_id)
        compute1.kill()
        compute2.kill()

    def test_least_busy_host_gets_volume_no_queue(self):
        """Ensures the host with less gigabytes gets the next one"""
        volume1 = service.Service('host1',
                                   'nova-volume',
                                   'volume',
                                   FLAGS.volume_manager)
        volume1.start()
        volume2 = service.Service('host2',
                                   'nova-volume',
                                   'volume',
                                   FLAGS.volume_manager)
        volume2.start()
        volume_id1 = self._create_volume()
        volume1.create_volume(self.context, volume_id1)
        volume_id2 = self._create_volume()
        host = self.scheduler.driver.schedule_create_volume(self.context,
                                                            volume_id2)
        self.assertEqual(host, 'host2')
        volume1.delete_volume(self.context, volume_id1)
        db.volume_destroy(self.context, volume_id2)

    def test_doesnt_report_disabled_hosts_as_up2(self):
        """Ensures driver doesn't find hosts before they are enabled"""
        compute1 = self.start_service('compute', host='host1')
        compute2 = self.start_service('compute', host='host2')
        s1 = db.service_get_by_args(self.context, 'host1', 'nova-compute')
        s2 = db.service_get_by_args(self.context, 'host2', 'nova-compute')
        db.service_update(self.context, s1['id'], {'disabled': True})
        db.service_update(self.context, s2['id'], {'disabled': True})
        hosts = self.scheduler.driver.hosts_up(self.context, 'compute')
        self.assertEqual(0, len(hosts))
        compute1.kill()
        compute2.kill()

    def test_reports_enabled_hosts_as_up(self):
        """Ensures driver can find the hosts that are up"""
        compute1 = self.start_service('compute', host='host1')
        compute2 = self.start_service('compute', host='host2')
        hosts = self.scheduler.driver.hosts_up(self.context, 'compute')
        self.assertEqual(2, len(hosts))
        compute1.kill()
        compute2.kill()

    def test_least_busy_host_gets_instance(self):
        """Ensures the host with less cores gets the next one"""
        s_ref = self._create_compute_service(host='host1')
        s_ref2 = self._create_compute_service(host='host2')
        instance_id1 = self._create_instance(host='host1')

        instance_id2 = self._create_instance()
        host = self.scheduler.driver.schedule_run_instance(self.context,
                                                           instance_id2)
        self.assertEqual(host, 'host2')
        db.instance_destroy(self.context, instance_id2)
        db.instance_destroy(self.context, instance_id1)
        db.service_destroy(self.context, s_ref['id'])
        db.service_destroy(self.context, s_ref2['id'])

    def test_specific_host_gets_instance(self):
        """Ensures if you set availability_zone it launches on that zone"""
        s_ref = self._create_compute_service(host='host1')
        compute1 = self.start_service('compute', host='host1')
        s_ref2 = self._create_compute_service(host='host2')
        instance_id1 = self._create_instance(host='host1', memory_mb='1')
        instance_id2 = self._create_instance(availability_zone='nova:host1')
        host = self.scheduler.driver.schedule_run_instance(self.context,
                                                           instance_id2)
        self.assertEqual('host1', host)
        db.instance_destroy(self.context, instance_id2)
        db.instance_destroy(self.context, instance_id1)
        db.service_destroy(self.context, s_ref['id'])
        db.service_destroy(self.context, s_ref2['id'])

    def test_no_oversubscription(self):
        """Ensures no oversubscription"""
        s_ref = self._create_compute_service(host='host1')
        instance_id1 = self._create_instance(host='host1')
        instance_id2 = self._create_instance()
        self.assertRaises(driver.NoValidHost,
                          self.scheduler.driver.schedule_run_instance,
                          self.context,
                          instance_id2)
        db.instance_destroy(self.context, instance_id2)
        db.instance_destroy(self.context, instance_id1)
        db.service_destroy(self.context, s_ref['id'])

    def test_reserved_memory(self):
        """Ensures no oversubscription"""
        FLAGS.cs_host_reserved_memory_mb = 36
        s_ref = self._create_compute_service(host='host1')
        instance_id1 = self._create_instance()
        self.assertRaises(driver.NoValidHost,
                          self.scheduler.driver.schedule_run_instance,
                          self.context,
                          instance_id1)
        db.instance_destroy(self.context, instance_id1)
        db.service_destroy(self.context, s_ref['id'])
        FLAGS.cs_host_reserved_memory_mb = 06

    def test_wont_sechedule_if_specified_host_is_down(self):
        compute1 = self.start_service('compute', host='host1')
        s1 = db.service_get_by_args(self.context, 'host1', 'nova-compute')
        now = utils.utcnow()
        delta = datetime.timedelta(seconds=FLAGS.service_down_time * 2)
        past = now - delta
        db.service_update(self.context, s1['id'], {'updated_at': past})
        instance_id2 = self._create_instance(availability_zone='nova:host1')
        self.assertRaises(driver.WillNotSchedule,
                          self.scheduler.driver.schedule_run_instance,
                          self.context,
                          instance_id2)
        db.instance_destroy(self.context, instance_id2)
        compute1.kill()

    def test_will_schedule_on_disabled_host_if_specified(self):
        s_ref = self._create_compute_service(host='host1')
        s1 = db.service_get_by_args(self.context, 'host1', 'nova-compute')
        db.service_update(self.context, s1['id'], {'disabled': True})
        instance_id2 = self._create_instance(availability_zone='nova:host1')
        host = self.scheduler.driver.schedule_run_instance(self.context,
                                                           instance_id2)
        self.assertEqual('host1', host)
        db.instance_destroy(self.context, instance_id2)
        db.service_destroy(self.context, s_ref['id'])

    def test_too_many_cores(self):
        """Ensures we don't go over max cores"""
        compute1 = self.start_service('compute', host='host1')
        compute2 = self.start_service('compute', host='host2')
        instance_ids1 = []
        instance_ids2 = []
        for index in xrange(FLAGS.max_cores):
            instance_id = self._create_instance()
            compute1.run_instance(self.context, instance_id)
            instance_ids1.append(instance_id)
            instance_id = self._create_instance()
            compute2.run_instance(self.context, instance_id)
            instance_ids2.append(instance_id)
        instance_id = self._create_instance()
        self.assertRaises(driver.NoValidHost,
                          self.scheduler.driver.schedule_run_instance,
                          self.context,
                          instance_id)
        db.instance_destroy(self.context, instance_id)
        for instance_id in instance_ids1:
            compute1.terminate_instance(self.context, instance_id)
        for instance_id in instance_ids2:
            compute2.terminate_instance(self.context, instance_id)
        compute1.kill()
        compute2.kill()

    def test_least_busy_host_gets_volume(self):
        """Ensures the host with less gigabytes gets the next one"""
        volume1 = self.start_service('volume', host='host1')
        volume2 = self.start_service('volume', host='host2')
        volume_id1 = self._create_volume()
        volume1.create_volume(self.context, volume_id1)
        volume_id2 = self._create_volume()
        host = self.scheduler.driver.schedule_create_volume(self.context,
                                                            volume_id2)
        self.assertEqual(host, 'host2')
        volume1.delete_volume(self.context, volume_id1)
        db.volume_destroy(self.context, volume_id2)
        volume1.kill()
        volume2.kill()

    def test_too_many_gigabytes(self):
        """Ensures we don't go over max gigabytes"""
        volume1 = self.start_service('volume', host='host1')
        volume2 = self.start_service('volume', host='host2')
        volume_ids1 = []
        volume_ids2 = []
        for index in xrange(FLAGS.max_gigabytes):
            volume_id = self._create_volume()
            volume1.create_volume(self.context, volume_id)
            volume_ids1.append(volume_id)
            volume_id = self._create_volume()
            volume2.create_volume(self.context, volume_id)
            volume_ids2.append(volume_id)
        volume_id = self._create_volume()
        self.assertRaises(driver.NoValidHost,
                          self.scheduler.driver.schedule_create_volume,
                          self.context,
                          volume_id)
        for volume_id in volume_ids1:
            volume1.delete_volume(self.context, volume_id)
        for volume_id in volume_ids2:
            volume2.delete_volume(self.context, volume_id)
        volume1.kill()
        volume2.kill()

    def test_scheduler_live_migration_with_volume(self):
        """scheduler_live_migration() works correctly as expected.

        Also, checks instance state is changed from 'running' -> 'migrating'.

        """

        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        dic = {'instance_id': instance_id, 'size': 1}
        v_ref = db.volume_create(self.context, dic)

        # cannot check 2nd argument b/c the addresses of instance object
        # is different.
        driver_i = self.scheduler.driver
        nocare = mox.IgnoreArg()
        self.mox.StubOutWithMock(driver_i, '_live_migration_src_check')
        self.mox.StubOutWithMock(driver_i, '_live_migration_dest_check')
        self.mox.StubOutWithMock(driver_i, '_live_migration_common_check')
        driver_i._live_migration_src_check(nocare, nocare)
        driver_i._live_migration_dest_check(nocare, nocare,
                                            i_ref['host'], False)
        driver_i._live_migration_common_check(nocare, nocare,
                                              i_ref['host'], False)
        self.mox.StubOutWithMock(rpc, 'cast', use_mock_anything=True)
        kwargs = {'instance_id': instance_id, 'dest': i_ref['host'],
                  'block_migration': False}
        rpc.cast(self.context,
                 db.queue_get_for(nocare, FLAGS.compute_topic, i_ref['host']),
                 {"method": 'live_migration', "args": kwargs})

        self.mox.ReplayAll()
        self.scheduler.live_migration(self.context, FLAGS.compute_topic,
                                      instance_id=instance_id,
                                      dest=i_ref['host'],
                                      block_migration=False)

        i_ref = db.instance_get(self.context, instance_id)
        self.assertTrue(i_ref['vm_state'] == vm_states.MIGRATING)
        db.instance_destroy(self.context, instance_id)
        db.volume_destroy(self.context, v_ref['id'])

    def test_live_migration_src_check_instance_not_running(self):
        """The instance given by instance_id is not running."""

        instance_id = self._create_instance(power_state=power_state.NOSTATE)
        i_ref = db.instance_get(self.context, instance_id)

        try:
            self.scheduler.driver._live_migration_src_check(self.context,
                                                            i_ref)
        except exception.Invalid, e:
            c = (e.message.find('is not running') > 0)

        self.assertTrue(c)
        db.instance_destroy(self.context, instance_id)

    def test_live_migration_src_check_volume_node_not_alive(self):
        """Raise exception when volume node is not alive."""

        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        dic = {'instance_id': instance_id, 'size': 1}
        v_ref = db.volume_create(self.context, {'instance_id': instance_id,
                                                'size': 1})
        t1 = utils.utcnow() - datetime.timedelta(1)
        dic = {'created_at': t1, 'updated_at': t1, 'binary': 'nova-volume',
               'topic': 'volume', 'report_count': 0}
        s_ref = db.service_create(self.context, dic)

        self.assertRaises(exception.VolumeServiceUnavailable,
                          self.scheduler.driver.schedule_live_migration,
                          self.context, instance_id, i_ref['host'])

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])
        db.volume_destroy(self.context, v_ref['id'])

    def test_live_migration_src_check_compute_node_not_alive(self):
        """Confirms src-compute node is alive."""
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        t = utils.utcnow() - datetime.timedelta(10)
        s_ref = self._create_compute_service(created_at=t, updated_at=t,
                                             host=i_ref['host'])

        self.assertRaises(exception.ComputeServiceUnavailable,
                          self.scheduler.driver._live_migration_src_check,
                          self.context, i_ref)

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_src_check_works_correctly(self):
        """Confirms this method finishes with no error."""
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        s_ref = self._create_compute_service(host=i_ref['host'])

        ret = self.scheduler.driver._live_migration_src_check(self.context,
                                                              i_ref)

        self.assertTrue(ret is None)
        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_dest_check_not_alive(self):
        """Confirms exception raises in case dest host does not exist."""
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        t = utils.utcnow() - datetime.timedelta(10)
        s_ref = self._create_compute_service(created_at=t, updated_at=t,
                                             host=i_ref['host'])

        self.assertRaises(exception.ComputeServiceUnavailable,
                          self.scheduler.driver._live_migration_dest_check,
                          self.context, i_ref, i_ref['host'], False)

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_dest_check_service_same_host(self):
        """Confirms exceptioin raises in case dest and src is same host."""
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        s_ref = self._create_compute_service(host=i_ref['host'])

        self.assertRaises(exception.UnableToMigrateToSelf,
                          self.scheduler.driver._live_migration_dest_check,
                          self.context, i_ref, i_ref['host'], False)

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_dest_check_service_lack_memory(self):
        """Confirms exception raises when dest doesn't have enough memory."""
        instance_id = self._create_instance()
        instance_id2 = self._create_instance(host='somewhere',
                                             memory_mb=12)
        i_ref = db.instance_get(self.context, instance_id)
        s_ref = self._create_compute_service(host='somewhere')

        self.assertRaises(exception.NovaException,
                          self.scheduler.driver._live_migration_dest_check,
                          self.context, i_ref, 'somewhere', False)

        db.instance_destroy(self.context, instance_id)
        db.instance_destroy(self.context, instance_id2)
        db.service_destroy(self.context, s_ref['id'])

    def test_block_migration_dest_check_service_lack_disk(self):
        """Confirms exception raises when dest doesn't have enough disk."""
        instance_id = self._create_instance()
        instance_id2 = self._create_instance(host='somewhere',
                                             local_gb=70, memory_mb=1)
        i_ref = db.instance_get(self.context, instance_id)
        s_ref = self._create_compute_service(host='somewhere')

        self.assertRaises(exception.MigrationError,
                          self.scheduler.driver._live_migration_dest_check,
                          self.context, i_ref, 'somewhere', True)

        db.instance_destroy(self.context, instance_id)
        db.instance_destroy(self.context, instance_id2)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_dest_check_service_works_correctly(self):
        """Confirms method finishes with no error."""
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        s_ref = self._create_compute_service(host='somewhere',
                                             memory_mb_used=5)

        ret = self.scheduler.driver._live_migration_dest_check(self.context,
                                                             i_ref,
                                                             'somewhere',
                                                             False)
        self.assertTrue(ret is None)
        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_common_check_service_orig_not_exists(self):
        """Destination host does not exist."""

        dest = 'dummydest'
        # mocks for live_migration_common_check()
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)
        t1 = utils.utcnow() - datetime.timedelta(10)
        s_ref = self._create_compute_service(created_at=t1, updated_at=t1,
                                             host=dest)

        # mocks for mounted_on_same_shared_storage()
        fpath = '/test/20110127120000'
        self.mox.StubOutWithMock(driver, 'rpc', use_mock_anything=True)
        topic = FLAGS.compute_topic
        driver.rpc.call(mox.IgnoreArg(),
            db.queue_get_for(self.context, topic, dest),
            {"method": 'create_shared_storage_test_file'}).AndReturn(fpath)
        driver.rpc.call(mox.IgnoreArg(),
            db.queue_get_for(mox.IgnoreArg(), topic, i_ref['host']),
            {"method": 'check_shared_storage_test_file',
             "args": {'filename': fpath}})
        driver.rpc.call(mox.IgnoreArg(),
            db.queue_get_for(mox.IgnoreArg(), topic, dest),
            {"method": 'cleanup_shared_storage_test_file',
             "args": {'filename': fpath}})

        self.mox.ReplayAll()
        #self.assertRaises(exception.SourceHostUnavailable,
        self.assertRaises(exception.FileNotFound,
                          self.scheduler.driver._live_migration_common_check,
                          self.context, i_ref, dest, False)

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])

    def test_live_migration_common_check_service_different_hypervisor(self):
        """Original host and dest host has different hypervisor type."""
        dest = 'dummydest'
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)

        # compute service for destination
        s_ref = self._create_compute_service(host=i_ref['host'])
        # compute service for original host
        s_ref2 = self._create_compute_service(host=dest, hypervisor_type='xen')

        # mocks
        driver = self.scheduler.driver
        self.mox.StubOutWithMock(driver, 'mounted_on_same_shared_storage')
        driver.mounted_on_same_shared_storage(mox.IgnoreArg(), i_ref, dest)

        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidHypervisorType,
                          self.scheduler.driver._live_migration_common_check,
                          self.context, i_ref, dest, False)

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])
        db.service_destroy(self.context, s_ref2['id'])

    def test_live_migration_common_check_service_different_version(self):
        """Original host and dest host has different hypervisor version."""
        dest = 'dummydest'
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)

        # compute service for destination
        s_ref = self._create_compute_service(host=i_ref['host'])
        # compute service for original host
        s_ref2 = self._create_compute_service(host=dest,
                                              hypervisor_version=12002)

        # mocks
        driver = self.scheduler.driver
        self.mox.StubOutWithMock(driver, 'mounted_on_same_shared_storage')
        driver.mounted_on_same_shared_storage(mox.IgnoreArg(), i_ref, dest)

        self.mox.ReplayAll()
        self.assertRaises(exception.DestinationHypervisorTooOld,
                          self.scheduler.driver._live_migration_common_check,
                          self.context, i_ref, dest, False)

        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])
        db.service_destroy(self.context, s_ref2['id'])

    def test_live_migration_common_check_checking_cpuinfo_fail(self):
        """Raise excetion when original host doen't have compatible cpu."""

        dest = 'dummydest'
        instance_id = self._create_instance()
        i_ref = db.instance_get(self.context, instance_id)

        # compute service for destination
        s_ref = self._create_compute_service(host=i_ref['host'])
        # compute service for original host
        s_ref2 = self._create_compute_service(host=dest)

        # mocks
        driver = self.scheduler.driver
        self.mox.StubOutWithMock(driver, 'mounted_on_same_shared_storage')
        driver.mounted_on_same_shared_storage(mox.IgnoreArg(), i_ref, dest)
        self.mox.StubOutWithMock(rpc, 'call', use_mock_anything=True)
        rpc.call(mox.IgnoreArg(), mox.IgnoreArg(),
            {"method": 'compare_cpu',
            "args": {'cpu_info': s_ref2['compute_node'][0]['cpu_info']}}).\
             AndRaise(rpc.RemoteError("doesn't have compatibility to", "", ""))

        self.mox.ReplayAll()
        try:
            self.scheduler.driver._live_migration_common_check(self.context,
                                                               i_ref,
                                                               dest,
                                                               False)
        except rpc.RemoteError, e:
            c = (e.message.find(_("doesn't have compatibility to")) >= 0)

        self.assertTrue(c)
        db.instance_destroy(self.context, instance_id)
        db.service_destroy(self.context, s_ref['id'])
        db.service_destroy(self.context, s_ref2['id'])


class CSMultiDriverTestCase(CSSimpleDriverTestCase):
    """Test case for multi driver."""

    def setUp(self):
        super(CSMultiDriverTestCase, self).setUp()
        self.flags(connection_type='fake',
                   stub_network=True,
                   max_cores=4,
                   max_gigabytes=4,
                   network_manager='nova.network.manager.FlatManager',
                   volume_driver='nova.volume.driver.FakeISCSIDriver',
                   compute_scheduler_driver=('cloudscaling.nova.scheduler'
                                             '.simple.SimpleScheduler'),
                   volume_scheduler_driver=('cloudscaling.nova.scheduler'
                                            '.simple.SimpleScheduler'),
                   scheduler_driver='nova.scheduler.multi.MultiScheduler')
        self.scheduler = manager.SchedulerManager()
