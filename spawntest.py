from functools import partial
import re

from kubernetes import client, config
from kubernetes.stream import stream

def pod_exec(cmd=None, cmd_set=None, stdout=True, stderr=False, api=None, name=None, namespace=None):

    if cmd is None:
        _cmd = cmd_set
    else:
        _cmd = cmd.split(' ')
        # exec_command = 'cat /etc/hosts'.split(' ')
    resp = stream(api.connect_get_namespaced_pod_exec,
                  name=name, namespace=namespace,
                  command=_cmd,
                  stderr=stdout, stdin=stderr, stdout=True, tty=False)
    return resp

def patch_hostaliases(app_id: str = None,
                      app_name: str = None,
                      app_group: str = None,
                      dict_appgroup: dict = None,
                      job_body_src: client.V1Job = None):

    list_host_aliases = []

    for app_key, app_spec in dict_appgroup.items():
        if app_id == app_key:
            pass
        else:
            list_host_aliases.append(client.V1HostAlias(
                ip=app_spec['ip'],
                hostnames=[app_key, app_spec['name']]
            ))
        continue

    job_body = job_body_src
    job_body.spec.template.spec.host_aliases = list_host_aliases
    # print(job_body)
    # body: client.V1Pod = dict_appgroup[app_id]['object']
    # body.spec.hostaliases = list_host_aliases

    # fin
    return list_host_aliases


def main():

    K8S_JOB_NAMESPACE = 'default'
    K8S_JOB_APPGROUP = "conda-workflow-2f3dutc1"
    enable_gpu = True
    gpus_per_pod = 1
    gpu_rsrc_name = 'nvidia.com/gpu'

    # config.load_kube_config(config_file="/home/xo/workspace/.kube/config")
    config.load_kube_config()
    api_instance_batch = client.BatchV1Api()
    api_instance_query = client.CoreV1Api()
    app_ids = ['leader', 'worker1', 'worker2']

    # ret = api_instance_batch.list_namespaced_job(namespace="default", watch=False,
    #                                              label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))
    # for item in ret.items:
    #     print("RET-ITEM:", item)
    #     print("name:", item.spec.template.spec)

    # ret = api_instance_query.list_namespaced_pod(namespace="default", watch=False,
    #                                              label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))
    # print('Listing pods with their IPs:')

    str_etc_hosts = ''
    str_etc_hostfile = ''
    # pattern = "([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)"
    pattern = "([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)"

    # dict_jobs = dict()
    # ret_jobs = api_instance_batch.list_namespaced_job(namespace="default", watch=False,
    #                                              label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))
    # for job in ret_jobs.items:
    #     app_id = re.search(pattern, job.metadata.name).group(4)
    #     dict_jobs.update({app_id: job})
    #     # print(job.spec.template.spec.host_aliases)
    #     continue

    ret_pods = api_instance_query.list_namespaced_pod(namespace="default", watch=False,
                                                      label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))
    dict_appgroup = dict()
    # print('Listing pods with their IPs:')
    for pod in ret_pods.items:
        app_id = re.search(pattern, pod.metadata.name).group(4)
        dict_appgroup.update({app_id: {
            "object": pod,
            "name": pod.metadata.name,
            "ip": pod.status.pod_ip,
            "phase": pod.status.phase,
            "slots": pod.spec.containers[0].resources.requests[gpu_rsrc_name] if enable_gpu else "1"
        }})
        continue

    for app_id in app_ids:
        str_etc_hosts += "{:s}\t{:s}\t{:s}\n".format(dict_appgroup[app_id]['ip'],
                                                     app_id, dict_appgroup[app_id]['name'], )
        str_etc_hostfile += "{:s}\tslots={:s}\n".format(app_id,
                                                        dict_appgroup[app_id]['slots'])
    for app_id in app_ids:

        # apply hostaliases

        # body_patch = patch_hostaliases(app_id=app_id, app_name=dict_appgroup[app_id]['name'],
        #                                app_group=K8S_JOB_APPGROUP, dict_appgroup=dict_appgroup,
        #                                job_body_src=dict_jobs[app_id])
        # # api_instance_query.patch_namespaced_pod()
        #
        # api_instance_batch.patch_namespaced_job(name=dict_jobs[app_id].metadata.name,
        #                                         namespace=K8S_JOB_NAMESPACE, body=body_patch)

        # update_status = api_instance_query.patch_namespaced_pod(
        #     name=dict_appgroup[app_id]['name'],
        #     namespace=K8S_JOB_NAMESPACE,
        #     body=body_patch)

        # print("Update status:", update_status)

        fn_pod_exec = partial(pod_exec,
                              api=api_instance_query,
                              name=dict_appgroup[app_id]['name'],
                              namespace=K8S_JOB_NAMESPACE,)
        hosts_src = fn_pod_exec('cat /etc/hosts',)

        # exec_command = 'cat /etc/hosts'.split(' ')
        # hosts_src = stream(api_instance_query.connect_get_namespaced_pod_exec,
        #               name=dict_appgroup[app_id]['name'],
        #               namespace=K8S_JOB_NAMESPACE,
        #               command=exec_command,
        #               stderr=False, stdin=False,
        #               stdout=True, tty=False)

        # building new hosts file
        list_hosts_items: list = hosts_src.split('\n')[:-2]
        list_hosts_items.append('')
        list_hosts_items.append('# MANUAL RESOLVE')
        list_hosts_items.extend(str_etc_hosts.split('\n'))

        hosts_new = '\n'.join(list_hosts_items)
        cmd_set_update = ['bash', '-c', 'cp /etc/hosts /etc/hosts.bkup;echo "{:s}" >/etc/hosts; cat /etc/hosts'.format(hosts_new)]
        # print(fn_pod_exec(cmd_set=cmd_set_update))

        # cmd_update = "bash -c \"cp /etc/hosts /etc/hosts.bkup; echo \'{:s}\'>/etc/hosts;\"".format(hosts_new)
        # print(cmd_update)
        # #
        # print(fn_pod_exec(cmd_update))
        print(fn_pod_exec("cat /etc/hosts"))

        continue

    # fin
    return


if __name__ == "__main__":
    main()
