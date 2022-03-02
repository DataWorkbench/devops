#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import sys
import time
import json
sys.path.append('.')
import subprocess
import ConfigParser
from optparse import OptionParser, OptionGroup
from cloud_platform import CloudPlatform


def exec_cmd(cmd, remote_host=None):
    '''
    try to execute command in a new process.
    argv:
        string. a command line.
    return:
        dict. a dict including returncode(int), stdout(string) and stderr(string).
    '''
    if remote_host:
        cmd = cmd.replace("$", r"\$")
        cmd = "ssh -o 'StrictHostKeyChecking no' -o 'UserKnownHostsFile /dev/null' root@{0} '{1}'".format(remote_host, cmd)

    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        ret = p.returncode
        out = out.strip()
        err = err.strip()
    except Exception as e:
        print("cmd [{0}] got exception {1}".format(cmd, e))

    result = {'ret':ret, 'out':out, 'err':err}
    return result


def safe_exec_cmd(cmd, remote_host=None):
    result = exec_cmd(cmd, remote_host)
    if result['ret'] != 0:
        print('The command [{0}] failed!'.format(cmd))
        sys.exit(1)


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

    def setstring(self, section, option, value):
        if value.startswith(('\'', '\"')) and value.endswith(('\'', '\"')):
            self.set(section=section, option=option, value=value[1:-1])
        else:
            self.set(section=section, option=option, value=value)

    def setint(self, section, option, value):
        self.set(section, option, value)


def devops_create(platform_conf_file, resource_conf_file):
    result = exec_cmd('ls {0}'.format(platform_conf_file))
    if result['ret'] != 0:
        print("Error: the platform conf file [{0}] does not exist!".format(platform_conf_file))
        sys.exit(1)
    platform_conf = Config(platform_conf_file)
    host = platform_conf.getstring('platform', 'host')
    result = exec_cmd('ping -c 1 {0}'.format(host))
    if result['ret'] != 0:
        result = exec_cmd('ping -c 1 {0}'.format(host))
        if result['ret'] != 0:
            print("Error: the platform api host [{0}] is unreachable, please check it!".format(host))
            sys.exit(1)
    cloud_platform = CloudPlatform(platform_conf_file)

    result = exec_cmd('ls {0}'.format(resource_conf_file))
    if result['ret'] != 0:
        print("Error: the resource conf file [{0}] does not exist!".format(resource_conf_file))
        sys.exit(1)
    resources = cloud_platform.create_resources(resource_conf_file)

    resources_json_file = './' + 'resources.{0}.json'.format(resources['uuid'])
    with open(resources_json_file, 'w') as json_file:
        json_file.write(json.dumps(resources, sort_keys=True, indent=2))
    print('You can find the resources json file [resources.{0}.json] in current directory.'.format(resources['uuid']))
    print('The firstbox eip address is [{0}].'.format(resources['firstbox_instance_eip']))
    return resources_json_file


def devops_delete(platform_conf_file, uuid, force_yes):
    result = exec_cmd('ls {0}'.format(platform_conf_file))
    if result['ret'] != 0:
        print("Error: the platform conf file [{0}] does not exist!".format(platform_conf_file))
        sys.exit(1)
    platform_conf = Config(platform_conf_file)
    host = platform_conf.getstring('platform', 'host')
    result = exec_cmd('ping -c 1 {0}'.format(host))
    if result['ret'] != 0:
        result = exec_cmd('ping -c 1 {0}'.format(host))
        if result['ret'] != 0:
            print("Error: the platform api host [{0}] is unreachable, please check it!".format(host))
            sys.exit(1)
    cloud_platform = CloudPlatform(platform_conf_file)

    if len(uuid) != 8:
        print("Error: the uuid you provide do not seem to be valid!")
        sys.exit(1)

    resources_json_file = './' + 'resources.{0}.json'.format(uuid)
    result = exec_cmd('ls {0}'.format(resources_json_file))
    if result['ret'] == 0:
        resources = exec_cmd('cat {0}'.format(resources_json_file))
        if resources['ret'] == 0:
            resources = json.loads(resources['out'])
            cloud_platform.delete_resources(resources, force_yes)
        safe_exec_cmd('rm -f {0}'.format(resources_json_file))
        print("The resources json file [{0}] has been removed!".format(resources_json_file))


def devops_deploy(resources_json_file, qingcloud_conf_file, platform_conf_file, retry=False, resource_type="standard"):
    result = exec_cmd('ls {0}'.format(platform_conf_file))
    if result['ret'] != 0:
        print("Error: the platform conf file [{0}] does not exist!".format(platform_conf_file))
        sys.exit(1)
    platform_conf = Config(platform_conf_file)
    host = platform_conf.getstring('platform', 'host')
    result = exec_cmd('ping -c 1 {0}'.format(host))
    if result['ret'] != 0:
        result = exec_cmd('ping -c 1 {0}'.format(host))
        if result['ret'] != 0:
            print("Error: the platform api host [{0}] is unreachable, please check it!".format(host))
            sys.exit(1)
    cloud_platform = CloudPlatform(platform_conf_file)

    result = exec_cmd('ls {0}'.format(resources_json_file))
    if result['ret'] != 0:
        print("Error: the resources json file [{0}] does not exist!".format(resources_json_file))
        sys.exit(1)
    with open(resources_json_file, 'r') as json_file:
        resources = json.load(json_file)
    firstbox_address = resources['firstbox_instance_eip']

    result = exec_cmd('ls {0}'.format(qingcloud_conf_file))
    if result['ret'] != 0:
        print("Error: the qingcloud conf file [{0}] does not exist!".format(qingcloud_conf_file))
        sys.exit(1)
    qingcloud_conf = Config(qingcloud_conf_file)
    installer_name = qingcloud_conf.getstring('qingcloud', 'installer_name')
    if not re.findall('qingcloud-installer', installer_name):
        print("pitrix-devops not support Installer 3.X!")
        sys.exit(1)

    if not retry:
        print("Downloading the pitrix installer package ...")
        result = exec_cmd('ls /root', firstbox_address)
        if result['ret'] != 0:
            print("Error: the firstbox [{0}] is unreachable, please check it!".format(firstbox_address))
            sys.exit(1)
        result = exec_cmd('ls /root/{0}'.format(installer_name), firstbox_address)
        if not re.findall(installer_name, result['out']):
            safe_exec_cmd('wget http://10.16.11.19/pi/{0} -P /root/'.format(installer_name), firstbox_address)

        print("Preparing the environment of qingcloud-firstbox ...")
        safe_exec_cmd('tar -zxf /root/{0}'.format(installer_name), firstbox_address)
        # set locale
        safe_exec_cmd("echo 'LANG=\\\"en_US.UTF-8\\\"' > /etc/default/locale", firstbox_address)
        safe_exec_cmd("echo 'LANGUAGE=\\\"en_US:en\\\"' >> /etc/default/locale", firstbox_address)
        safe_exec_cmd("echo 'LC_ALL=\\\"en_US.UTF-8\\\"' >> /etc/default/locale", firstbox_address)
        success_output = 'The installer is bootstrapped successfully'
        result = exec_cmd('grep "{0}" /root/deploy.log'.format(success_output), firstbox_address)
        if result['out'] == "":
            # new a tmux session
            exec_cmd('tmux kill-session -t deploy', firstbox_address)
            safe_exec_cmd('tmux new -s deploy -d', firstbox_address)
            safe_exec_cmd('tmux send-keys -t deploy /root/qingcloud-installer/bootstrap/deploy.sh Enter', firstbox_address)
            time.sleep(5)

            while True:
                result = exec_cmd('grep "{0}" /root/deploy.log'.format(success_output), firstbox_address)
                if result['out'] != "":
                    # new line
                    print("")
                    # kill a tmux session
                    safe_exec_cmd('tmux kill-session -t deploy', firstbox_address)
                    break
                fail_output = 'Exec the function .* Error!'
                result = exec_cmd('egrep "{0}" /root/deploy.log'.format(fail_output), firstbox_address)
                if result['out'] != "":
                    print("Bootstrap in firstbox failed!")
                    sys.exit(1)
                else:
                    sys.stdout.write('.')
                    sys.stdout.flush()
                time.sleep(5)

    exec_cmd('rm -rf /root/devops', firstbox_address)
    safe_exec_cmd('ssh root@{0} "mkdir -p /root/devops/"'.format(firstbox_address))
    safe_exec_cmd('scp -p -r -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" devops/enable-eips.py root@{0}:/root/devops/enable-eips.py'.format(firstbox_address))
    safe_exec_cmd('scp -p -r -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" devops/devops_{0}.py root@{1}:/root/devops/devops.py'.format(resource_type, firstbox_address))
    safe_exec_cmd('scp -p -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" {0} root@{1}:/root/devops/resources.json'.format(resources_json_file, firstbox_address))
    safe_exec_cmd('scp -p -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" {0} root@{1}:/root/devops/qingcloud.conf'.format(qingcloud_conf_file, firstbox_address))

    # new a tmux session
    exec_cmd('tmux kill-session -t devops', firstbox_address)
    safe_exec_cmd('tmux new -s devops -d', firstbox_address)
    if retry:
        safe_exec_cmd('tmux send-keys -t devops "/root/devops/devops.py -C" Enter', firstbox_address)
    else:
        safe_exec_cmd('tmux send-keys -t devops "/root/devops/devops.py" Enter', firstbox_address)
    time.sleep(5)

    old_status = ''
    old_index = 0
    wait_job = False
    while True:
        status_array = exec_cmd('cat /root/devops/status', firstbox_address)['out'].split('\n')
        new_status = status_array[-1]
        if new_status == "Failed":
            if wait_job:
                # new line
                print("")
            print("Deploy QingCloud failed")
            sys.exit(1)
        elif new_status == "Success":
            break
        elif new_status != old_status:
            if wait_job:
                # new line
                print("")
                wait_job = False

            while old_index < len(status_array):
                print(status_array[old_index])
                old_index += 1
            old_status = status_array[-1]
        else:
            if old_status:
                sys.stdout.write('.')
                sys.stdout.flush()
                wait_job = True
        time.sleep(5)
    # kill a tmux session
    safe_exec_cmd('tmux kill-session -t devops', firstbox_address)

    if resource_type == "express":
        router_id = resources['mgmt_router_id']
        vpc_address = resources['mgmt_router_eip']
    else:
        vg_num = resources['vg_num']
        if vg_num > 0:
            router_id = resources['public_router_id']
            vpc_address = resources['public_router_eip']
        else:
            router_id = resources['mgmt_router_id']
            vpc_address = resources['mgmt_router_eip']

    safe_exec_cmd('export PYTHONPATH=/pitrix/lib/pitrix-installer-common:${PYTHONPATH};/pitrix/bin/dump_hosts.py -f /tmp/hosts_devops', firstbox_address)
    proxy_floating_ip = exec_cmd('cat /tmp/hosts_devops', firstbox_address)['out'].split('\n')[0].split()[0]
    # new line
    print("")
    cloud_platform.add_static_router(router_id, proxy_floating_ip)
    print("Deploy QingCloud success")
    old_hosts = exec_cmd('cat /tmp/hosts_devops', firstbox_address)['out'].split('\n')
    for old_host in old_hosts:
        print('{0} {1}'.format(vpc_address, ' '.join(old_host.split()[1:])))


def main(args):
    usage = '%prog [options]'
    version = '%prog 1.3'
    parser = OptionParser(usage=usage, version=version)

    # public options
    parser.add_option(
        '-f', '--force-yes', action='store_const', const=1,
        dest='force_yes', help='''Input y/yes automatically when need to confirm.'''
    )
    parser.add_option(
        '-p', '--platform_conf', action='store', type='string', metavar='PLATFORM_CONF',
        dest='platform_conf_file', help='''The conf file of the platform you want to put your virtual resources. e.g. <./platform.conf>.'''
    )

    # resources options
    parser_resources_group = OptionGroup(
        parser, "Resources Options",
        "These options provide the arguments about resources, including create resources and delete resources."
    )
    parser_resources_group.add_option(
        '-c', '--create', action='store_const', const=1,
        dest='create', help='''Whether to create a set of virtual resources.'''
    )
    parser_resources_group.add_option(
        '-r', '--resource_conf', action='store', type='string', metavar='RESOURCE_CONF',
        dest='resource_conf_file', help='''The conf file of the resource you want to create. e.g. <./resource.conf>.'''
    )
    parser_resources_group.add_option(
        '-d', '--delete', action='store_const', const=1,
        dest='delete', help='''Whether to delete a set of virtual resources.'''
    )
    parser_resources_group.add_option(
        '-u', '--uuid', action='store', type='string', metavar='UUID',
        dest='uuid', help='''The uuid of virtual resources you created.'''
    )
    parser_resources_group.add_option(
        '-t', '--resource_type', action='store', type='string', metavar='RESOURCE_TYPE',
        dest='resource_type', help='''The type of the specified resource, Optional value are [standard, express].'''
    )
    parser.add_option_group(parser_resources_group)

    # deployment options
    parser_deployment_group = OptionGroup(
        parser, "Deployment Options",
        "These options provide the arguments about deployment."
    )
    parser_deployment_group.add_option(
        '-D', '--deploy', action='store_const', const=1,
        dest='deploy', help='''Whether to deploy a qingcloud using the virtual resources you created.'''
    )
    parser_deployment_group.add_option(
        '-R', '--resources_json', action='store', type='string', metavar='RESOURCES_JSON',
        dest='resources_json_file', help='''The json file of virtual resources you created. e.g. <./resources.xxx.json>.'''
    )
    parser_deployment_group.add_option(
        '-Q', '--qingcloud_conf', action='store', type='string', metavar='QINGCLOUD_CONF',
        dest='qingcloud_conf_file', help='''The conf file of qingcloud you want to deploy on virtual resources. e.g. <./qingcloud.conf>.'''
    )
    parser_deployment_group.add_option(
        '-C', '--retry', action='store_const', const=True,
        dest='retry', help='''Continue the job of failure.'''
    )
    parser.add_option_group(parser_deployment_group)

    (options, args_left) = parser.parse_args(args=args[1:])
    if len(args_left) != 0:
        print('There is something wrong with the arguments you input.')
        print('Arguments: {0} can not be parsed.'.format(args_left))
        sys.exit(1)

    CWD = os.getcwd()

    if options.force_yes == 1:
        force_yes = True
    else:
        force_yes = False

    if options.retry:
        retry = True
    else:
        retry = False


    if not options.platform_conf_file and not options.create and not options.resource_conf_file and not options.delete and not options.uuid and \
            not options.deploy and not options.resources_json_file and not options.qingcloud_conf_file:
        print('You do not input any arguments.''')
        print('It will create the virtual resources using "./platform.conf" and "./resource.conf".')
        print('And it will deploy qingcloud using "./qingcloud.conf" on these virtual resources.')

        if force_yes == False:
            value = raw_input('Input "y" to continue and "n" to exit: ')
            if value == 'y' or value == 'Y' or value == 'yes' or value == 'Yes':
                confirm = True
            else:
                confirm = False
        else:
            confirm = True

        if confirm == True:
            platform_conf_file = './platform.conf'
            resource_conf_file = './resource.conf'
            resources_json_file = devops_create(platform_conf_file, resource_conf_file)
            qingcloud_conf_file = './qingcloud.conf'
            devops_deploy(resources_json_file, qingcloud_conf_file, platform_conf_file, retry)
        else:
            exit(1)

    if options.create == 1:
        if not options.platform_conf_file:
            platform_conf_file = "{0}/platform.conf".format(CWD)
            print("The configuration files [platform.conf] uses the current directory")
        else:
            platform_conf_file = options.platform_conf_file

        if not options.resource_conf_file:
            resource_conf_file = '{0}/resource.conf'.format(CWD)
            print("The configuration files [resource.conf] uses the current directory")
        else:
            resource_conf_file = options.resource_conf_file

        devops_create(platform_conf_file, resource_conf_file)

    if options.delete == 1:
        if not options.uuid:
            print('If you want to delete resources, please input the arguments <uuid>!')
            sys.exit(1)
        if not options.platform_conf_file:
            platform_conf_file = "{0}/platform.conf".format(CWD)
            print("The configuration files [platform.conf] uses the current directory")
        else:
            platform_conf_file = options.platform_conf_file
        uuid = options.uuid
        devops_delete(platform_conf_file, uuid, force_yes)

    if options.deploy == 1:
        if not options.resources_json_file:
            print('If you want to deploy qingcloud, please input the arguments <resources_json>!')
            sys.exit(1)
        else:
            resources_json_file = options.resources_json_file

        if not options.qingcloud_conf_file:
            qingcloud_conf_file = "{0}/qingcloud.conf".format(CWD)
            print("The configuration files [qingcloud.conf] uses the current directory")
        else:
            qingcloud_conf_file = options.qingcloud_conf_file

        if not options.platform_conf_file:
            platform_conf_file = "{0}/platform.conf".format(CWD)
            print("The configuration files [platform.conf] uses the current directory")
        else:
            platform_conf_file = options.platform_conf_file

        devops_deploy(resources_json_file, qingcloud_conf_file, platform_conf_file, retry)


if (__name__ == '__main__'):
    main(sys.argv)
