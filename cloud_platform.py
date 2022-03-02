#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import utils
import random
import string
import ConfigParser
import qingcloud.iaas
import qingcloud.misc
from datetime import datetime


NODE_RULES = [
    {
        'security_group_rule_name':'ssh',
        'priority':'1',
        'direction':'0',
        'action':'accept',
        'protocol':'tcp',
        'val1':'22',
        'val2':'22',
        'val3':''
    },
    {
        'security_group_rule_name':'http',
        'priority':'1',
        'direction':'0',
        'action':'accept',
        'protocol':'tcp',
        'val1':'80',
        'val2':'80',
        'val3':''
    }
]

LB_RULES = [
    {
        'security_group_rule_name':'http',
        'priority':'1',
        'direction':'0',
        'action':'accept',
        'protocol':'tcp',
        'val1':'80',
        'val2':'80',
        'val3':''
    },
    {
        'security_group_rule_name':'kubesphere',
        'priority':'1',
        'direction':'0',
        'action':'accept',
        'protocol':'tcp',
        'val1':'30880',
        'val2':'30880',
        'val3':''
    },
    {
        'security_group_rule_name':'https',
        'priority':'1',
        'direction':'0',
        'action':'accept',
        'protocol':'tcp',
        'val1':'443',
        'val2':'443',
        'val3':''
    }
]


class Config(ConfigParser.ConfigParser):
    def __init__(self, config_file):
        ConfigParser.ConfigParser.__init__(self)
        self.read(config_file)

    def getstring(self, section, option):
        value = self.get(section, option)
        if value.startswith(('\'', '\"')) and value.endswith(('\'', '\"')):
            new_value = value[1:-1]
        else:
            new_value = value
        return new_value


def type2spec(instance_type):
    '''
    transfer the instance type to instance spec including CPU number and memory size.
    '''
    for i in range(len(instance_type)):
        if instance_type[i] == 'm':
            index = i
            break
    cpu = int(instance_type[1:index])
    memory = int(instance_type[(index+1):])
    instance_spec = {'cpu':cpu, 'memory':memory}
    return instance_spec


def int2mask(mask_int):
    bin_list = ['0' for i in range(32)]
    for i in range(mask_int):
        bin_list[i] = '1'
    mask_bin = [''.join(bin_list[(i*8):(i*8+8)]) for i in range(4)]
    mask_list = [str(int(j, 2)) for j in mask_bin]
    return '.'.join(mask_list)


class CloudPlatform(qingcloud.iaas.connection.APIConnection):
    def __init__(self, platform_conf_file):
        platform_conf = Config(platform_conf_file)
        access_key_id = platform_conf.getstring('platform', 'access_key_id')
        self.access_key_id = access_key_id
        secret_access_key = platform_conf.getstring('platform', 'secret_access_key')
        self.secret_access_key = secret_access_key
        zone = platform_conf.getstring('platform', 'zone').lower()
        host = platform_conf.getstring('platform', 'host')
        port = int(platform_conf.getstring('platform', 'port'))
        protocol = platform_conf.getstring('platform', 'protocol')
        super(CloudPlatform, self).__init__(access_key_id, secret_access_key, zone, host, port, protocol, debug=True)

    def run_instances(self, image_id,
                      instance_type=None,
                      cpu=None,
                      memory=None,
                      count=1,
                      instance_name="",
                      vxnets=None,
                      security_group=None,
                      login_mode=None,
                      login_keypair=None,
                      login_passwd=None,
                      need_newsid=False,
                      volumes=None,
                      cpu_model=None,
                      need_userdata=0,
                      userdata_type=None,
                      userdata_value=None,
                      userdata_path=None,
                      instance_class=None,
                      hostname=None,
                      place_group_id=None,
                      repl=None,
                      instance_group=None,
                      **ignore):
        action = qingcloud.iaas.constants.ACTION_RUN_INSTANCES
        valid_keys = ['image_id', 'instance_type', 'cpu', 'memory', 'count',
                      'instance_name', 'vxnets', 'security_group', 'login_mode',
                      'login_keypair', 'login_passwd', 'need_newsid',
                      'volumes', 'cpu_model', 'need_userdata', 'userdata_type',
                      'userdata_value', 'userdata_path', 'instance_class',
                      'hostname', 'place_group_id', 'repl', 'instance_group'
                      ]
        body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
        if not self.req_checker.check_params(body,
                                             required_params=['image_id'],
                                             integer_params=['count', 'cpu', 'memory', 'need_newsid',
                                                             'need_userdata', 'instance_class'],
                                             list_params=['volumes']
                                             ):
            return None
        return self.send_request(action, body)

    def create_volumes(self, size,
                       volume_name="",
                       volume_type=0,
                       count=1,
                       target_user=None,
                       place_group_id=None,
                       repl=None,
                       **ignore):
        action = qingcloud.iaas.constants.ACTION_CREATE_VOLUMES
        valid_keys = ['size', 'volume_name', 'volume_type', 'count',
                       'target_user', 'place_group_id', 'repl']
        body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
        if not self.req_checker.check_params(body,
                                             required_params=['size'],
                                             integer_params=['size', 'count'],
                                             list_params=[]
                                             ):
            return None

        return self.send_request(action, body)


    def allocate_eips(self, bandwidth,
                      billing_mode=qingcloud.iaas.constants.EIP_BILLING_MODE_BANDWIDTH,
                      count=1,
                      need_icp=0,
                      eip_name='',
                      eip_group=None,
                      **ignore):
        action = qingcloud.iaas.constants.ACTION_ALLOCATE_EIPS
        valid_keys = ['bandwidth', 'billing_mode',
                      'count', 'need_icp', 'eip_name', 'eip_group']
        body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
        if not self.req_checker.check_params(body,
                                             required_params=['bandwidth'],
                                             integer_params=[
                                                 'bandwidth', 'count', 'need_icp'],
                                             list_params=[]
                                             ):
            return None
        return self.send_request(action, body)

    def describe_users(self):
        action = 'DescribeUsers'
        body = {}
        if not self.req_checker.check_params(body,
                                             required_params=[],
                                             ):
            return None
        return self.send_request(action, body)

    def describe_keypairs(self, keypairs=None,
                           encrypt_method=None,
                           search_word=None,
                           owner=None,
                           verbose=0,
                           offset=None,
                           limit=None,
                           tags=None,
                           **ignore):
        action = qingcloud.iaas.constants.ACTION_DESCRIBE_KEY_PAIRS
        valid_keys = ['keypairs', 'encrypt_method', 'search_word', 'verbose',
                      'offset', 'limit', 'tags', 'owner']
        body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
        if not self.req_checker.check_params(body,
                                             required_params=[],
                                             integer_params=[
                                                 'offset', 'limit', 'verbose'],
                                             list_params=['keypairs', 'tags']
                                             ):
            return None
        return self.send_request(action, body)

    def wait_jobs_successful(self, job_ids, interval=10, retry=50):
        count = 0
        while count < retry:
            ret = self.describe_jobs(jobs=job_ids)
            job_set = ret['job_set']
            failed_job_ids = []
            not_successful_job_ids = []
            for job in job_set:
                if job['status'] == "failed":
                    failed_job_ids.append(job['job_id'])
                elif job['status'] != 'successful':
                    not_successful_job_ids.append(job['job_id'])
                else:
                    continue

            if len(failed_job_ids) != 0:
                print "The jobs [{0}] are failed, auto clean up self.resources.".format(failed_job_ids)
                self.delete_resources(self.resources, False)
                exit(1)
            elif len(not_successful_job_ids) == 0:
                break
            count += 1
            time.sleep(interval)
        if len(not_successful_job_ids) != 0:
            print "Wait for jobs {0} to be successful time out".format(not_successful_job_ids)
            exit(1)


    def wait_volumes_available(self, volume_ids, interval=10, retry=50):
        count = 0
        while count < retry:
            ret = self.describe_volumes(volumes=volume_ids)
            volume_set = ret['volume_set']
            not_available_volume_ids = []
            for volume in volume_set:
                if volume['status'] != 'available':
                    not_available_volume_ids.append(volume['volume_id'])
            if len(not_available_volume_ids) == 0:
                break
            count += 1
            time.sleep(interval)
        if len(not_available_volume_ids) != 0:
            print "Wait for volumes {0} to be available time out".format(not_available_volume_ids)
            exit(1)

    def wait_instances_running(self, instance_ids, interval=10, retry=50):
        count = 0
        while count < retry:
            ret = self.describe_instances(instances=instance_ids)
            instance_set = ret['instance_set']
            not_running_instance_ids = []
            for instance in instance_set:
                if instance['status'] != 'running':
                    not_running_instance_ids.append(instance['instance_id'])
            if len(not_running_instance_ids) == 0:
                break
            count += 1
            time.sleep(interval)
        if len(not_running_instance_ids) != 0:
            print "Wait for instances {0} to be running time out".format(not_running_instance_ids)
            exit(1)

    def safe_run_api(self, api, **kwargs):
        try:
            func = getattr(self, api)
        except AttributeError:
            print "The API [{0}] does not exist!".format(api)
        ret_code = 1
        retry_count = 0
        while ret_code != 0:
            ret = func(**kwargs)
            ret_code = ret['ret_code']
            retry_count += 1
            if ret_code != 0 and retry_count > 2:
                print "The API [{0}] failed! ".format(api)
                print ret
                print "\n  Now you can select to destroy the self.resources of [%s] or not." % self.uuid
                print "  If you want to delete the self.resources later, you can use the follow command."
                print "  [python devops.py -p platform.conf -d -u %s]\n" % self.uuid
                self.delete_resources(self.resources, False)
                exit(1)
        return ret

    def create_loadbalancers(self, loadbalancer_name, security_group, eips=[], vxnet=None,
                            loadbalancer_type=0, backend_ip_version=4,
                            node_count=2, cluster_mode=0, mode=1,**ignore):
            action = qingcloud.iaas.constants.ACTION_CREATE_LOADBALANCER
            valid_keys = ['loadbalancer_name', 'eips', 'security_group',
                          'vxnet',
                          'loadbalancer_type', 'backend_ip_version',
                          'node_count', 'cluster_mode', 'mode']
            body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
            if not self.req_checker.check_params(body,
                                                 required_params=['loadbalancer_name', 'security_group',],
                                                 integer_params=[
                                                     'loadbalancer_type', 'backend_ip_version',
                                                     'node_count', 'cluster_mode', 'mode'],
                                                 list_params=['eips']
                                                 ):
                return None
            return self.send_request(action, body)

    def add_loadbalancer_listeners(self, listeners, loadbalancer,**ignore):
            action = qingcloud.iaas.constants.ACTION_ADD_LOADBALANCER_LISTENERS
            valid_keys = ['listeners',
                          'loadbalancer']
            body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
            if not self.req_checker.check_params(body,
                                                 required_params=[
                                                     'listeners','loadbalancer'],
                                                 list_params=[
                                                     'listeners'],
                                                 ):
                return None
            return self.send_request(action, body)

    def update_loadbalancers(self, loadbalancers,**ignore):
            action = qingcloud.iaas.constants.ACTION_UPDATE_LOADBALANCERS
            valid_keys = ['loadbalancers']
            body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
            if not self.req_checker.check_params(body,
                                                 required_params=[
                                                     'loadbalancers',],
                                                 list_params=[
                                                     'loadbalancers'],
                                                 ):
                return None
            return self.send_request(action, body)

    def add_loadbalancer_backends(self, loadbalancer_listener, backends=[], **ignore):
            action = qingcloud.iaas.constants.ACTION_ADD_LOADBALANCER_BACKENDS
            valid_keys = ['loadbalancer_listener', 'backends']
            body = qingcloud.misc.utils.filter_out_none(locals(), valid_keys)
            if not self.req_checker.check_params(body,
                                                 required_params=[
                                                     'loadbalancer_listener',
                                                     'backends',],
                                                 list_params=[
                                                     'backends'],
                                                 ):
                return None
            return self.send_request(action, body)

    def create_instance_groups(self, instance_num, instance_group_name, per_num_each_group=0):
        dt = datetime.now()
        current_time = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        action = 'CreateInstanceGroups'
        instance_groups = []
        instance_group_num = 0
        if per_num_each_group != 0:
            if instance_num % per_num_each_group == 0:
                instance_group_num = instance_num / per_num_each_group
            else:
                instance_group_num = instance_num / per_num_each_group + 1
        else:
            instance_group_num = 1
        params = {
            "signature_version": 1,
            "signature_method": "HmacSHA256",
            "version": 1,
            "access_key_id": self.access_key_id,
            "time_stamp": current_time,
            "action": action,
            "instance_group_name": instance_group_name,
            "relation": "repel",
            "zone": self.zone,
            "count": instance_group_num}
        resp = utils.send_request(action, params, self.secret_access_key, 'http://' + self.host,
                                  self.zone)
        if resp:
            instance_groups = resp['instance_groups']
        return instance_groups

    def create_security_group(self, security_group_name, target_user=None,
                              is_trusted='1', **ignore):
        """ Create a new security group without any rule.
        @param security_group_name: the name of the security group you want to create.
        @param target_user: ID of user who will own this resource, should be one of your sub-accounts
        """
        action = "CreateSecurityGroup"
        body = {'security_group_name': security_group_name,"is_trusted":is_trusted}
        if target_user:
            body['target_user'] = target_user
        if not self.conn.req_checker.check_params(body,
                                                  required_params=[
                                                      'security_group_name'],
                                                  integer_params=[],
                                                  list_params=[]
                                                  ):
            return None

        return self.conn.send_request(action, body)

    def get_instance_groups(self, uuid):
        action = 'DescribeInstanceGroups'
        dt = datetime.now()
        current_time = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        instance_groups = []
        params = {
            "signature_version": 1,
            "signature_method": "HmacSHA256",
            "version": 1,
            "access_key_id": self.access_key_id,
            "time_stamp": current_time,
            "action": action,
            "instance_group_name": uuid
            }
        resp = utils.send_request(action, params, self.secret_access_key, 'http://' + self.host,
                                  self.zone)
        if resp:
            for i in range(0, len(resp['instance_group_set'])):
                instance_groups.append(resp['instance_group_set'][i]['instance_group_id'])
        return instance_groups

    def delete_instance_groups(self, instance_groups):
        action = 'DeleteInstanceGroups'
        dt = datetime.now()
        current_time = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        params = {
            "signature_version": 1,
            "signature_method": "HmacSHA256",
            "version": 1,
            "access_key_id": self.access_key_id,
            "time_stamp": current_time,
            "action": action,
            }
        for i in range(0, len(instance_groups)):
            params["instance_groups.%s" % (i+1)] = instance_groups[i]
        resp = utils.send_request(action, params, self.secret_access_key, 'http://' + self.host,
                                  self.zone)
        return resp

    def cease_instances(self, instance_ids):
        action = 'CeaseInstances'
        dt = datetime.now()
        current_time = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        params = {
            "signature_version": 1,
            "signature_method": "HmacSHA256",
            "version": 1,
            "access_key_id": self.access_key_id,
            "time_stamp": current_time,
            "action": action,
            }
        for i in range(0, len(instance_ids)):
            params["instances.%s" % (i+1)] = instance_ids[i]
        resp = utils.send_request(action, params, self.secret_access_key, 'http://' + self.host,
                                  self.zone)
        return resp

    def create_resources(self, resource_conf_file):
        resource_conf = Config(resource_conf_file)
        public_key = resource_conf.getstring('resource', 'public_key')

        uuid = resource_conf.getstring('resource', 'uuid')
        if uuid == 'auto_generated':
            uuid = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        elif len(uuid) == 8:
            uuid = uuid
        else:
            print 'Error: The uuid [{0}] you provide is not a valid uuid.'.format(uuid)
            exit(1)
        self.uuid = uuid
        print 'The self.resources uuid you will create is [{0}].'.format(uuid)

        firstbox_cpu = int(resource_conf.getstring('resource', 'firstbox_cpu'))
        firstbox_memory = int(
            resource_conf.getstring('resource', 'firstbox_memory'))
        firstbox_image = resource_conf.getstring('resource', 'firstbox_image')
        firstbox_instance_type = resource_conf.getstring('resource', 'firstbox_instance_type')

        master_num = int(resource_conf.getstring('resource', 'master_num'))
        master_cpu = int(resource_conf.getstring('resource', 'master_cpu'))
        master_memory = int(resource_conf.getstring('resource', 'master_memory'))
        master_image = resource_conf.getstring('resource', 'master_image')
        master_instance_class = resource_conf.getstring('resource', 'master_instance_class')
        master_volume_type = resource_conf.getstring('resource', 'master_volume_type')
        master_volume_size = resource_conf.getstring('resource', 'master_volume_size')
        master_instance_type = resource_conf.getstring('resource', 'master_instance_type')

        worker_num = int(resource_conf.getstring('resource', 'worker_num'))
        worker_cpu = int(resource_conf.getstring('resource', 'worker_cpu'))
        worker_memory = int(
            resource_conf.getstring('resource', 'worker_memory'))
        worker_image = resource_conf.getstring('resource', 'worker_image')
        worker_instance_class = resource_conf.getstring('resource', 'worker_instance_class')
        worker_volume_type = resource_conf.getstring('resource', 'worker_volume_type')
        worker_volume_size = resource_conf.getstring('resource', 'worker_volume_size')
        worker_instance_type = resource_conf.getstring('resource', 'worker_instance_type')


        vxnet_id = resource_conf.getstring('resource', 'vxnet_id')



        self.resources = {}
        self.resources['uuid'] = uuid
        self.resources['master_num'] = master_num
        self.resources['master_cpu'] = master_cpu
        self.resources['master_memory'] = master_memory
        self.resources['master_image'] = master_image

        self.resources['worker_num'] = worker_num
        self.resources['worker_cpu'] = worker_cpu
        self.resources['worker_memory'] = worker_memory
        self.resources['worker_image'] = worker_image


        print "Creating security group ..."
        ret = self.safe_run_api(
            'create_security_group',
            security_group_name='security-group'
        )
        security_group_id = ret['security_group_id']
        self.resources['security_group_id'] = security_group_id



        print "Adding security group rules ..."
        ret = self.safe_run_api(
            'add_security_group_rules',
            security_group=security_group_id,
            rules=NODE_RULES
        )

        print "Applying the security group ..."
        ret = self.safe_run_api(
            'apply_security_group',
            security_group=security_group_id
        )
        apply_security_group_job_id = ret['job_id']
        print "Waiting apply security group to finish ..."
        self.wait_jobs_successful(job_ids=[apply_security_group_job_id], retry=80)

        print "Creating lb security group ..."
        ret = self.safe_run_api(
            'create_security_group',
            security_group_name='lb-security-group'
        )
        lb_security_group_id = ret['security_group_id']
        self.resources['lb_security_group_id'] = lb_security_group_id

        print "Adding lb security group rules ..."
        ret = self.safe_run_api(
            'add_security_group_rules',
            security_group=lb_security_group_id,
            rules=LB_RULES
        )

        print "Applying the lb security group ..."
        ret = self.safe_run_api(
            'apply_security_group',
            security_group=lb_security_group_id
        )
        apply_security_group_job_id = ret['job_id']
        print "Waiting apply lb security group to finish ..."
        self.wait_jobs_successful(job_ids=[apply_security_group_job_id],
                                  retry=80)

        print "Creating keypair ..."
        ret = self.safe_run_api(
            'create_keypair',
            keypair_name='keypair',
            mode='user',
            public_key=public_key
        )
        keypair_id = ret['keypair_id']
        self.resources['keypair_id'] = keypair_id

        print "Running firstbox instance ..."
        ret = self.safe_run_api(
            'run_instances',
            image_id=firstbox_image,
            cpu=firstbox_cpu,
            memory=firstbox_memory,
            instance_type=firstbox_instance_type,
            instance_name='firstbox',
            login_mode='keypair',
            login_keypair=keypair_id,
            hostname='firstbox',
            vxnets=[vxnet_id],
            cpu_model='IceLake',
            security_group=security_group_id,
        )
        run_instances_job_id = ret['job_id']
        firstbox_instance_id = ret['instances'][0]
        self.resources['firstbox_instance_id'] = firstbox_instance_id
        print "Waiting run firstbox instance to finish ..."
        self.wait_jobs_successful([run_instances_job_id])
        self.wait_instances_running([firstbox_instance_id])
        ret = self.describe_instances(instances=[firstbox_instance_id])
        firstbox_instance_set = ret['instance_set']

        print "Allocating eip for firstbox instance ..."
        ret = self.safe_run_api(
            'allocate_eips',
            bandwidth=4,
            billing_mode="traffic",
            eip_name='firstbox-eip',
            eip_group='eipg-00000000'
        )
        firstbox_instance_eip_id = ret['eips'][0]
        self.resources['firstbox_instance_eip_id'] = firstbox_instance_eip_id

        print "Waiting for firstbox instance eip ready ..."
        time.sleep(5)

        print "Getting firstbox instance eip address ..."
        ret = self.safe_run_api('describe_eips',
                                eips=[firstbox_instance_eip_id])
        firstbox_instance_eip = ret['eip_set'][0]['eip_addr']
        self.resources['firstbox_instance_eip'] = firstbox_instance_eip

        print "Associating eip to firstbox instance ..."
        ret = self.safe_run_api(
            'associate_eip',
            eip=firstbox_instance_eip_id,
            instance=firstbox_instance_id
        )
        associate_eip_job_id = ret['job_id']
        print "Waiting associate firstbox instance eip to finish ..."
        self.wait_jobs_successful([associate_eip_job_id])

        print "Creating master instance group"
        master_instance_groups = self.create_instance_groups(master_num, 'master_instance_groups')
        self.resources['master_instance_groups'] = master_instance_groups
        print "Create master instance group" + str(master_instance_groups)

        print "Creating volumes for master"
        create_master_volumes_job_ids = []
        master_pitrix_volume_ids = []
        for i in range(0, master_num):
            ret = self.safe_run_api(
                'create_volumes',
                size=master_volume_size,
                volume_name='master-volume-'+str(i+1),
                volume_type=master_volume_type
            )
            create_master_volumes_job_ids.append(ret['job_id'])
            master_pitrix_volume_ids.extend(ret['volumes'])
        self.resources['master_pitrix_volume_ids'] = master_pitrix_volume_ids
        print "Waiting create master volumes to finish ..."
        self.wait_jobs_successful(create_master_volumes_job_ids)
        self.wait_volumes_available(master_pitrix_volume_ids)
        print "Create volumes for master" + str(master_pitrix_volume_ids)

        print "Running master instances with volumes ..."
        run_master_instances_job_ids = []
        master_instance_ids = []
        master_instance_hostnames = []
        master_instance_id_hostname_dict = {}
        for i in range(0, master_num):
            name_prefix = 'master-'
            hostname = name_prefix + '0'*(2-len(str(i+1))) +str(i + 1)

            ret = self.safe_run_api(
                'run_instances',
                image_id=master_image,
                cpu=master_cpu,
                memory=master_memory,
                instance_type=master_instance_type,
                instance_name=hostname,
                hostname=hostname,
                login_mode='keypair',
                login_keypair=keypair_id,
                vxnets=[vxnet_id],
                volumes=[master_pitrix_volume_ids[i]],
                cpu_model='IceLake',
                instance_class=master_instance_class,
                instance_group=master_instance_groups[-1],
                security_group=security_group_id,
            )
            run_master_instances_job_ids.append(ret['job_id'])
            node_instance_id = ret['instances'][0]
            master_instance_ids.append(node_instance_id)
            master_instance_hostnames.append(hostname)
            master_instance_id_hostname_dict[node_instance_id] = hostname
        self.resources['master_instance_ids'] = master_instance_ids
        self.resources['master_instance_hostnames'] = master_instance_hostnames
        self.resources['master_instance_id_hostname_dict'] = master_instance_id_hostname_dict
        print "Waiting run master instances to finish ..."
        self.wait_jobs_successful(run_master_instances_job_ids)
        self.wait_instances_running(master_instance_ids, retry=300)
        ret = self.describe_instances(instances=master_instance_ids)
        master_instance_set = ret['instance_set']
        print "Run master instances to finish " + str(master_instance_ids)

        print "Creating worker instance group"
        worker_instance_groups = self.create_instance_groups(worker_num,
                                                             'worker_instance_groups')
        self.resources['worker_instance_groups'] = worker_instance_groups
        print "Create worker instance group" + str(worker_instance_groups)

        print "Creating volumes for worker"
        create_worker_volumes_job_ids = []
        worker_pitrix_volume_ids = []
        for i in range(0, worker_num):
            ret = self.safe_run_api(
                'create_volumes',
                size=worker_volume_size,
                volume_name='worker-volume-' + str(i + 1),
                volume_type=worker_volume_type
            )
            create_worker_volumes_job_ids.append(ret['job_id'])
            worker_pitrix_volume_ids.extend(ret['volumes'])
        self.resources['worker_pitrix_volume_ids'] = worker_pitrix_volume_ids
        print "Waiting create work volumes to finish ..."
        self.wait_jobs_successful(create_worker_volumes_job_ids)
        self.wait_volumes_available(worker_pitrix_volume_ids)
        print "Create work volumes to finish " + str(worker_pitrix_volume_ids)

        print "Running worker instances with volumes ..."
        run_worker_instances_job_ids = []
        worker_instance_ids = []
        worker_instance_hostnames = []
        worker_instance_id_hostname_dict = {}
        for i in range(0, worker_num):
            name_prefix = 'worker-s'
            hostname = name_prefix + '0'*(3-len(str(i+1))) +str(i + 1)

            ret = self.safe_run_api(
                'run_instances',
                image_id=worker_image,
                cpu=worker_cpu,
                memory=worker_memory,
                instance_type=worker_instance_type,
                instance_name=hostname,
                hostname=hostname,
                login_mode='keypair',
                login_keypair=keypair_id,
                vxnets=[vxnet_id],
                volumes=[worker_pitrix_volume_ids[i]],
                cpu_model='IceLake',
                instance_class=worker_instance_class,
                instance_group=worker_instance_groups[-1],
                security_group=security_group_id,
            )
            run_worker_instances_job_ids.append(ret['job_id'])
            worker_instance_id = ret['instances'][0]
            worker_instance_ids.append(worker_instance_id)
            worker_instance_hostnames.append(hostname)
            worker_instance_id_hostname_dict[worker_instance_id] = hostname
        self.resources['worker_instance_ids'] = worker_instance_ids
        self.resources['worker_instance_hostnames'] = worker_instance_hostnames
        self.resources[
            'worker_instance_id_hostname_dict'] = worker_instance_id_hostname_dict
        print "Waiting run worker instances to finish ..."
        self.wait_jobs_successful(run_worker_instances_job_ids)
        self.wait_instances_running(worker_instance_ids, retry=300)
        ret = self.describe_instances(instances=worker_instance_ids)
        worker_instance_set = ret['instance_set']

        print "Run worker instances to finish " + str(worker_instance_ids)

        print "Waiting for the worker instances ready ..."
        time.sleep(5)

        print "Create internal loadbalancer ..."
        ret = self.safe_run_api(
            'create_loadbalancers',
            loadbalancer_name="internal_lb",
            security_group=security_group_id,
            vxnet=vxnet_id
        )
        create_loadbalancers_job_id = ret['job_id']
        internal_lb_id = ret['loadbalancer_id']
        self.resources['internal_lb_id'] = internal_lb_id
        self.wait_jobs_successful([create_loadbalancers_job_id])
        ret = self.safe_run_api(
            'describe_loadbalancers',
            loadbalancers=[internal_lb_id],
        )
        internal_lb = ret['loadbalancer_set'][0]

        print "Add internal loadbalancer listener..."
        ret = self.safe_run_api(
            'add_loadbalancer_listeners',
            listeners=[{"loadbalancer_listener_name":"ks-apiserver",
                        "listener_protocol":"http",
                        "listener_port":"6443",
                        "balance_mode":"roundrobin",
                        "session_sticky":"",
                        "healthy_check_method":"tcp",
                        "healthy_check_option":"10|5|2|5",
                        "scene":1,"forwardfor_item":"1",
                        "timeout":"50","tunnel_timeout":"3600",
                        "listener_option":0,
                        "backend_protocol":"http",
                        "forwardfor":0}],
            loadbalancer=internal_lb_id
        )
        internal_lb_listener_id = ret['loadbalancer_listeners'][0]
        ret = self.safe_run_api(
            'update_loadbalancers',
            loadbalancers=[internal_lb_id]
        )
        update_loadbalancers_job_id = ret['job_id']
        self.wait_jobs_successful([update_loadbalancers_job_id])
        ret = self.safe_run_api(
            'add_loadbalancer_backends',
            loadbalancer_listener=internal_lb_listener_id,
            backends=[{"loadbalancer_backend_name":"ks-master","backup":"0","resource_id":instance['instance_id'],"port":"6443","weight":"1"} for instance in master_instance_set]
        )
        ret = self.safe_run_api(
            'update_loadbalancers',
            loadbalancers=[internal_lb_id]
        )
        update_loadbalancers_job_id = ret['job_id']
        self.wait_jobs_successful([update_loadbalancers_job_id])
        print "Add internal loadbalancer listener finished..."

        print "Create internal loadbalancer finished"

        print "Create external loadbalancer ..."

        print "Allocating eip for external loadbalancer ..."
        ret = self.safe_run_api(
            'allocate_eips',
            bandwidth=4,
            billing_mode="traffic",
            eip_name='lb-eip',
            eip_group='eipg-00000000'
        )
        lb_eip_id = ret['eips'][0]
        self.resources['lb_eip_id'] = lb_eip_id
        ret = self.safe_run_api(
            'create_loadbalancers',
            loadbalancer_name="external_lb",
            security_group=lb_security_group_id,
            vxnet=vxnet_id,
            eips=[lb_eip_id]
        )
        create_loadbalancers_job_id = ret['job_id']
        external_lb_id = ret['loadbalancer_id']
        self.resources['external_lb_id'] = external_lb_id
        self.wait_jobs_successful([create_loadbalancers_job_id])

        print "Add external loadbalancer listener..."
        ret = self.safe_run_api(
            'add_loadbalancer_listeners',
            listeners=[{"loadbalancer_listener_name": "kubesphere-web",
                        "listener_protocol": "http",
                        "listener_port": "30880",
                        "balance_mode": "roundrobin",
                        "session_sticky": "",
                        "healthy_check_method": "tcp",
                        "healthy_check_option": "10|5|2|5",
                        "scene": 1, "forwardfor_item": "1",
                        "timeout": "50", "tunnel_timeout": "3600",
                        "listener_option": 0,
                        "backend_protocol": "http",
                        "forwardfor": 0}],
            loadbalancer=external_lb_id,
        )
        external_lb_listener_id = ret['loadbalancer_listeners'][0]
        ret = self.safe_run_api(
            'update_loadbalancers',
            loadbalancers=[external_lb_id]
        )
        update_loadbalancers_job_id = ret['job_id']
        self.wait_jobs_successful([update_loadbalancers_job_id])
        ret = self.safe_run_api(
            'add_loadbalancer_backends',
            loadbalancer_listener=external_lb_listener_id,
            backends=[{"loadbalancer_backend_name": "kubesphere-web", "backup": "0",
                       "resource_id": instance['instance_id'], "port": "30880",
                       "weight": "1"} for instance in master_instance_set]
        )
        ret = self.safe_run_api(
            'update_loadbalancers',
            loadbalancers=[external_lb_id]
        )
        update_loadbalancers_job_id = ret['job_id']
        self.wait_jobs_successful([update_loadbalancers_job_id])
        print "Add external loadbalancer listener finished..."


        print "Creating ipset..."
        all_nodes_ip = []
        print master_instance_set
        print worker_instance_set
        for instance in master_instance_set + worker_instance_set:
            for vxnet in instance['vxnets']:
                if vxnet['vxnet_id'] == vxnet_id:
                    all_nodes_ip.append(vxnet['private_ip'])
        ret = self.safe_run_api(
            'create_security_group_ipset',
            security_group_ipset_name='all_nodes_ip',
            ipset_type='0',
            val="\r,".join(all_nodes_ip + internal_lb['private_ips'])
        )
        all_nodes_ip_ipset_id = ret['security_group_ipset_id']
        self.resources['all_nodes_ip_ipset_id'] = all_nodes_ip_ipset_id
        print "Adding security group rules ..."
        ret = self.safe_run_api(
            'add_security_group_rules',
            security_group=security_group_id,
            rules=[
                {"security_group_rule_name":"all-nodes",
                 "priority":"1","direction":"0",
                 "action":"accept","protocol":"tcp",
                 "val1":"","val2":"",
                 "val3":all_nodes_ip_ipset_id,
                 "rule_action":"accept"}]
        )

        print "Applying the security group ..."
        ret = self.safe_run_api(
            'apply_security_group',
            security_group=security_group_id
        )
        apply_security_group_job_id = ret['job_id']
        print "Waiting apply security group to finish ..."
        self.wait_jobs_successful(job_ids=[apply_security_group_job_id],
                                  retry=80)


        print "Virtual resources are created successfully."
        return self.resources


    def delete_resources(self, resources, force_yes=False):
        print 'Start delete resources...'
        instance_group_ids = []
        instance_group_id_keys = ['master_instance_groups', 'worker_instance_groups']
        for key in instance_group_id_keys:
            if key in resources:
                instance_group_ids.extend(resources.get(key, ""))
        instance_ids = []
        instance_id_keys = ['master_instance_ids', 'worker_instance_ids', 'firstbox_instance_id']
        for key in instance_id_keys:
            if isinstance(resources.get(key, ""), list):
                if key in resources:
                    instance_ids.extend(resources.get(key, []))
            else:
                if key in resources:
                    instance_ids.append(resources.get(key, ""))
        volume_ids = []
        volume_id_keys = ['master_pitrix_volume_ids', 'worker_pitrix_volume_ids']
        for key in volume_id_keys:
            if key in resources:
                volume_ids.extend(resources.get(key, ""))

        eip_ids = []
        eip_id_keys = ['firstbox_instance_eip_id', 'lb_eip_id']
        for key in eip_id_keys:
            if key in resources:
                eip_ids.append(resources.get(key, ""))

        keypair_ids = []
        keypair_id_keys = ['keypair_id']
        for key in keypair_id_keys:
            if key in resources:
                keypair_ids.append(resources.get(key, ""))

        security_group_ids = []
        security_group_id_keys = ['security_group_id', 'lb_security_group_id']
        for key in security_group_id_keys:
            if key in resources:
                security_group_ids.append(resources.get(key, ""))

        lb_ids = []
        lb_id_keys = ['external_lb_id', 'internal_lb_id']
        for key in lb_id_keys:
            if key in resources:
                lb_ids.append(resources.get(key, ""))

        ipset_ids = []
        ipset_id_keys = ['all_nodes_ip_ipset_id']
        for key in ipset_id_keys:
            if key in resources:
                ipset_ids.append(resources[key])


        print "instance ids: " + str(instance_ids)
        print "instance group ids: " + str(instance_group_ids)
        print "volume ids: " + str(volume_ids)
        print "eip ids: " + str(eip_ids)
        print "keypair ids: " + str(keypair_ids)
        print "security group ids: " + str(security_group_ids)
        print "lb ids: " + str(lb_ids)
        print "ipset ids: " + str(ipset_ids)

        if instance_ids != []:
            print 'Terminating the instances ...'
            ret = self.safe_run_api(
                'terminate_instances',
                instances=instance_ids,
                unlease=0
            )
            terminate_instances_job_id = ret['job_id']
            print 'Waiting terminate instances to finish ...'
            self.wait_jobs_successful([terminate_instances_job_id])
            ret = self.cease_instances(instance_ids)
            if not ret:
                print 'Ceasing the instances failed.'
            else:
                self.wait_jobs_successful([ret['job_id']])

        if lb_ids != []:
            print 'delete the lbs...'
            ret = self.safe_run_api(
                'delete_loadbalancers',
                loadbalancers=lb_ids
            )
            delete_loadbalancers_job_id=ret['job_id']
            print 'Waiting delete loadbalancers to finish ...'
            self.wait_jobs_successful([delete_loadbalancers_job_id])

        time.sleep(10)
        if instance_group_ids != []:
            print 'Deleting the instance groups ...'
            ret = self.delete_instance_groups(instance_group_ids)
            if not ret:
                print 'Deleting the instance groups failed.'

        if volume_ids != []:
            print 'Deleting the volumes ...'
            ret = self.safe_run_api(
                'delete_volumes',
                volumes=volume_ids,
                unlease=0
            )
            delete_volumes_job_id = ret['job_id']
            print 'Waiting delete volumes to finish ...'
            self.wait_jobs_successful([delete_volumes_job_id])

        if eip_ids != []:
            print 'Releasing the eips ...'
            ret = self.safe_run_api(
                'release_eips',
                eips=eip_ids
            )
            release_eips_job_id = ret['job_id']
            print 'Waiting release eips to finish ...'
            self.wait_jobs_successful([release_eips_job_id])

        if security_group_ids != []:
            print 'Deleting the security groups ...'
            ret = self.safe_run_api(
                'delete_security_groups',
                security_groups=security_group_ids
            )

        if keypair_ids != []:
            print 'Deleting the keypairs ...'
            ret = self.safe_run_api(
                'delete_keypairs',
                keypairs=keypair_ids
            )

        if ipset_ids != []:
            print 'Deleting the ipsets ...'
            ret = self.delete_security_group_ipsets(ipset_ids)

        print 'All virtual resources are deleted successfully.'






