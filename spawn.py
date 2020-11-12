from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from functools import partial
import random
import re
import sys
from time import sleep, time

from kubernetes import client, config
from kubernetes.stream import stream


def ssh_keygen(type: str = 'rsa', decode2str: bool = True):

    # very handy SSH prv/pub keygen
    # references:
    # - https://stackoverflow.com/a/39126754
    # - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519.html

    if type == 'rsa':
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                       backend=crypto_default_backend())

    _key_private = key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption()
    )

    _key_public = key.public_key().public_bytes(
        encoding=crypto_serialization.Encoding.OpenSSH,
        format=crypto_serialization.PublicFormat.OpenSSH
    )

    dict_keygen = {
        'prv_fname': "id_{:s}".format(type),
        'prv_key': _key_private.decode('UTF-8') if decode2str else _key_private,
        'pub_fname': "id_{:s}.pub".format(type),
        'pub_key': _key_public.decode('UTF-8') if decode2str else _key_public,
    }

    return dict_keygen


def JobTemplate(app_group: str = None, app_id: str = None,
                c8s_img: str = None, enable_gpu: bool = False, gpus_per_pod: int = 0,
                list_k8s_volumes: list = None, list_c8s_vol_mntdest: list = None, list_env_vars: list = None):

    app_name = "{:s}-{:s}".format(app_group, app_id)

    gpu_req_dict = {"nvidia.com/gpu": str(gpus_per_pod)} if enable_gpu else None
    body = client.V1Job(api_version="batch/v1",
                        kind="Job",
                        metadata=client.V1ObjectMeta(name=app_name),
                        spec=client.V1JobSpec(
                            template=client.V1PodTemplateSpec(
                                metadata=client.V1ObjectMeta(labels={"app": app_name, "appgroup": app_group},),
                                spec=client.V1PodSpec(
                                    containers=[client.V1Container(
                                        name="condaenv-exporter", image=c8s_img,
                                        resources=client.V1ResourceRequirements(
                                            limits=gpu_req_dict, requests=gpu_req_dict
                                        ) if enable_gpu else None,
                                        volume_mounts=list_c8s_vol_mntdest,
                                        env=list_env_vars
                                    )],
                                    volumes=list_k8s_volumes,
                                    restart_policy="Never"
                                )
                            )
                        ))
    # fin
    return body


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


def kill_appgroup(k8s_apis, appgroup, delay: float or int = 0):

    if delay > 0:
        sleep(delay)
    else:
        pass

    try:
        k8s_apis['Batch'].delete_collection_namespaced_job(
            namespace="default", label_selector='appgroup={:s}'.format(appgroup))
    except KeyError:
        pass
    try:
        k8s_apis['Core'].delete_collection_namespaced_pod(
            namespace="default", label_selector='appgroup={:s}'.format(appgroup))
    except KeyError:
        pass

    exit(0)

    # fin
    return


def main():

    # safety-pin
    sleep(3)

    # argv
    SU_USR = sys.argv[1]
    SU_UID = sys.argv[2]
    SU_GID = sys.argv[3]
    EXPORTMODE = "WETRUN"
    SRCENVNAME = sys.argv[4]
    WETRUNARGS = sys.argv[5]
    WETRUNLOGF = sys.argv[6]

    K8S_JOB_NAMESPACE = 'default'
    K8S_JOB_NAME_DEF = "conda-workflow"
    c8s_image_tag = "registry.zyn.kr:6543/dataon.kr/condaenv-exporter:0.3.5-cuda10.0"
    enable_gpu = True
    gpus_per_pod = 1
    # gpu_rsrc_name = 'amd.com/gpu'
    gpu_rsrc_name = 'nvidia.com/gpu'

    # random alphanumeric sequence template
    random_choice_seq = ''.join(str(idx) for idx in range(10)) + ''.join(chr(idx+97) for idx in range(26))
    K8S_JOB_POSTFIX = ''.join(random.choice(random_choice_seq) for _ in range(8))

    # other configs
    CONDAEVAL = 'eval "$(/opt/conda/bin/conda shell.bash hook)";'
    K8S_JOB_COUNTS = 3
    K8S_JOB_APPGROUP = "{:s}-{:s}".format(K8S_JOB_NAME_DEF, K8S_JOB_POSTFIX)
    K8S_JOB_INIT_TIMEOUT = 120
    K8S_JOB_ARGS = "mpirun --hostfile /etc/hostfile -np {:d} bash -c '{:s}conda activate tf114;python workspace/horovod_test/tensorflow_mnist.py;'"

    # check input arguments
    print("{:s} - {:s} - {:s}".format(SU_USR, SU_UID, SU_GID))
    print("{:s}".format(K8S_JOB_APPGROUP))

    dict_keygen = ssh_keygen(type='rsa')

    list_k8s_volumes = [
        client.V1Volume(name="conda-pubenvs",
                        nfs=client.V1NFSVolumeSource(
                            path="/home/xo/miniconda3/tmp",
                            read_only=True,
                            server="ipa-k1805.zyn.kr")),
        client.V1Volume(name="conda-usrenvs",
                        nfs=client.V1NFSVolumeSource(
                            path="/home/xo/miniconda3/envs",
                            read_only=False,
                            server="ipa-k1805.zyn.kr")),
        client.V1Volume(name="workspace",
                        nfs=client.V1NFSVolumeSource(
                            path="/home/xo",
                            read_only=False,
                            server="ipa-k1805.zyn.kr"
                        ))
    ]
    list_c8s_vol_mntdest = [
        client.V1VolumeMount(name="conda-pubenvs", mount_path="/opt/conda/pubenvs"),
        client.V1VolumeMount(name="conda-usrenvs", mount_path="/opt/conda/usrenvs"),
        client.V1VolumeMount(name="workspace", mount_path="/mnt/workspace"),
    ]
    list_env_vars = [
        client.V1EnvVar(name="NB_USER", value=SU_USR),
        client.V1EnvVar(name="NB_UID", value=SU_UID),
        client.V1EnvVar(name="NB_GID", value=SU_GID),
        client.V1EnvVar(name="SRCENVNAME", value=SRCENVNAME),
        client.V1EnvVar(name="EXPORTMODE", value=EXPORTMODE),
        client.V1EnvVar(name="WETRUNARGS", value=WETRUNARGS),
        client.V1EnvVar(name="LOGFILE", value=WETRUNLOGF),
        client.V1EnvVar(name="LAP", value="FALSE"),
        client.V1EnvVar(name="CONDA_DEFAULT_THREADS", value="10"),
        client.V1EnvVar(name="ENABLESSHD", value="TRUE")
    ]

    # init k8s client & apis
    config.load_kube_config()
    k8s_apis = {'Batch': client.BatchV1Api(), 'Core': client.CoreV1Api()}

    # set hosts & workers (num: total job count-1)
    app_ids = ['leader']
    app_ids.extend(["worker{:d}".format(idx+1) for idx in range(K8S_JOB_COUNTS-1)])

    for app_id in app_ids:
        job_object_body = JobTemplate(app_group=K8S_JOB_APPGROUP, app_id=app_id,
                                      c8s_img=c8s_image_tag, enable_gpu=enable_gpu, gpus_per_pod=gpus_per_pod,
                                      list_k8s_volumes=list_k8s_volumes,
                                      list_c8s_vol_mntdest=list_c8s_vol_mntdest,
                                      list_env_vars=list_env_vars)
        k8s_apis['Batch'].create_namespaced_job(namespace=K8S_JOB_NAMESPACE, body=job_object_body)

    # waiting for all elems in appgroup is okay and literally 'Running'
    t_start = None
    while True:
        if t_start is None:
            t_start = time()
        else:
            pass

        ret = k8s_apis['Core'].list_namespaced_pod(namespace="default", watch=False)
        all_valid = True
        for pod in ret.items:
            if pod.status.phase.lower() == 'running':
                continue
            else:
                all_valid = False
                break
        if all_valid:
            break
        else:
            # check timeout reach
            if abs(time()-t_start) >= K8S_JOB_INIT_TIMEOUT:
                print('[E] Timeout reached.\nQuitting...')
                kill_appgroup(k8s_apis=k8s_apis, appgroup=K8S_JOB_APPGROUP)
            else:
                # if any elem is not okay, wait 2 secs and loop again
                sleep(2)
            continue

    # after all success spawn
    str_etc_hosts = ''
    str_etc_hostfile = ''
    pattern = "([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)-([a-z0-9]+)"

    ret = k8s_apis['Core'].list_namespaced_pod(namespace=K8S_JOB_NAMESPACE, watch=False,
                                               label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))

    dict_appgroup = dict()
    # print('Listing pods with their IPs:')
    for pod in ret.items:
        app_id = re.search(pattern, pod.metadata.name).group(4)
        try:
            mpi_slots = pod.spec.containers[0].resources.requests[gpu_rsrc_name] if enable_gpu else "1"
        except KeyError:
            print('[E] current spawn status does not meet pre-defined requirements.\nQuitting...')
            kill_appgroup(k8s_apis=k8s_apis, appgroup=K8S_JOB_APPGROUP)
            mpi_slots = None
        dict_appgroup.update({app_id: {
            "object": pod,
            "name": pod.metadata.name,
            "ip": pod.status.pod_ip,
            "phase": pod.status.phase,
            "slots": mpi_slots
        }})

    # upddate for manual resolve (/etc/hosts, /etc/hostfile)
    for app_id in app_ids:
        str_etc_hosts += "{:s}\t{:s}\t{:s}\n".format(dict_appgroup[app_id]['ip'],
                                                     app_id, dict_appgroup[app_id]['name'])
        str_etc_hostfile += "{:s}\tslots={:s}\n".format(app_id,
                                                        dict_appgroup[app_id]['slots'])

    for app_id in app_ids:
        # reference: https://github.com/kubernetes-client/python/issues/878#issuecomment-511319318

        fn_pod_exec = partial(pod_exec,
                              api=k8s_apis['Core'],
                              name=dict_appgroup[app_id]['name'],
                              namespace=K8S_JOB_NAMESPACE, )
        # get src hosts file
        hosts_src = fn_pod_exec('cat /etc/hosts', )

        # building new hosts file
        list_hosts_items: list = hosts_src.split('\n')[:-2]
        list_hosts_items.append('')
        list_hosts_items.append('# MANUAL RESOLVE')
        list_hosts_items.extend(str_etc_hosts.split('\n'))
        hosts_new = '\n'.join(list_hosts_items)
        cmd_set_update_hosts = [
            'bash', '-c',
            'cp /etc/hosts /etc/hosts.bkup;' +
            'echo "{:s}" >/etc/hosts;'.format(hosts_new) +
            'echo "{:s}" >/etc/hostfile;'.format(str_etc_hostfile)
        ]
        fn_pod_exec(cmd_set=cmd_set_update_hosts)

        # building ssh credentials
        sshcfg = '\n'.join([
            'Host *', '    ServerAliveInterval 45', '    ServerAliveCountMax 1920', '    StrictHostKeyChecking no'
        ])
        cmd_set_update_sshkey = [
            'bash', '-c',
            'mkdir -p /home/{:s}/.ssh;'.format(SU_USR) +
            'echo "{:s}" >> /home/{:s}/.ssh/{:s};'.format(dict_keygen['prv_key'], SU_USR, dict_keygen['prv_fname']) +
            'echo "{:s}" >> /home/{:s}/.ssh/{:s};'.format(dict_keygen['pub_key'], SU_USR, dict_keygen['pub_fname']) +
            'echo "{:s}" >> /home/{:s}/.ssh/authorized_keys;'.format(dict_keygen['pub_key'], SU_USR) +
            'echo "{:s}" >> /home/{:s}/.ssh/config;'.format(sshcfg, SU_USR) +
            'chmod 600 /home/{:s}/.ssh/*;'.format(SU_USR) +
            'chown -R {:s}:{:s} /home/{:s}/.ssh;'.format(SU_UID, SU_GID, SU_USR)
        ]
        fn_pod_exec(cmd_set=cmd_set_update_sshkey)

        continue
    del fn_pod_exec

    print("----------")
    fn_pod_exec = partial(pod_exec,
                          api=k8s_apis['Core'],
                          name=dict_appgroup['leader']['name'],
                          namespace=K8S_JOB_NAMESPACE,)
    cmd_set_job = [
        'su', '-', SU_USR, '-c',
        K8S_JOB_ARGS.format(K8S_JOB_COUNTS, CONDAEVAL)
    ]
    print(fn_pod_exec(cmd_set=cmd_set_job, stderr=True))
    print("----------")

    # final step for blowing jobs/pods
    kill_appgroup(k8s_apis=k8s_apis, appgroup=K8S_JOB_APPGROUP, delay=40)

    # fin
    return


if __name__ == "__main__":
    main()
