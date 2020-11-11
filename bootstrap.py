from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import os
import random
import sys
import time

from kubernetes import client, config


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


def main():

    # safety-pin
    time.sleep(3)

    # argv
    SU_USR = sys.argv[1]
    SU_UID = sys.argv[2]
    SU_GID = sys.argv[3]
    EXPORTMODE = "WETRUN"
    SRCENVNAME = sys.argv[4]
    WETRUNARGS = sys.argv[5]
    WETRUNLOGF = sys.argv[6]

    K8S_JOB_NAME_DEF = "conda-workflow"
    c8s_image_tag = "registry.zyn.kr:6543/dataon.kr/condaenv-exporter:0.3.5-cuda10.0"

    # random alphanumeric sequence template
    random_choice_seq = ''.join(str(idx) for idx in range(10)) + ''.join(chr(idx+97) for idx in range(26))
    K8S_JOB_POSTFIX = ''.join(random.choice(random_choice_seq) for _ in range(8))
    K8S_JOB_COUNTS = 3
    K8S_JOB_APPGROUP = "{:s}-{:s}".format(K8S_JOB_NAME_DEF, K8S_JOB_POSTFIX)

    # check input arguments
    print("{:s} - {:s} - {:s}".format(SU_USR, SU_UID, SU_GID))
    print("{:s}".format(K8S_JOB_APPGROUP))

    # very handy SSH prv/pub keygen
    # references:
    # - https://stackoverflow.com/a/39126754
    # - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519.html

    key = ed25519.Ed25519PrivateKey.generate()
    prv_ed25519_key = key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption()
    ).decode('UTF-8')
    pub_ed25519_key = key.public_key().public_bytes(
        encoding=crypto_serialization.Encoding.OpenSSH,
        format=crypto_serialization.PublicFormat.OpenSSH
    ).decode('UTF-8')

    # print("----------")
    # print(prv_ed25519_key)
    # print("----------")
    # print(pub_ed25519_key)

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

    config.load_kube_config()
    api_instance_batch = client.BatchV1Api()
    api_instance_query = client.CoreV1Api()
    app_ids = ['leader', 'worker1', 'worker2']

    for app_id in app_ids:
        job_object_body = JobTemplate(app_group=K8S_JOB_APPGROUP, app_id=app_id,
                                      c8s_img=c8s_image_tag, enable_gpu=True, gpus_per_pod=1,
                                      list_k8s_volumes=list_k8s_volumes,
                                      list_c8s_vol_mntdest=list_c8s_vol_mntdest,
                                      list_env_vars=list_env_vars)
        api_instance_batch.create_namespaced_job(namespace="default", body=job_object_body)

    while True:
        ret = api_instance_query.list_namespaced_pod(namespace="default", watch=False)
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
            time.sleep(3)
            continue

    # after all success spawn
    ret = api_instance_query.list_namespaced_pod(namespace="default", watch=False,
                                                 label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))
    print('Listing pods with their IPs:')
    for pod in ret.items:
        print("{:s}\t{:s}\t{:s}".format(pod.metadata.name, pod.status.pod_ip, pod.status.phase))

    time.sleep(10)
    api_instance_batch.delete_collection_namespaced_job(namespace="default",
                                                        label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))
    api_instance_query.delete_collection_namespaced_pod(namespace="default",
                                                        label_selector='appgroup={:s}'.format(K8S_JOB_APPGROUP))

    # fin
    return


if __name__ == "__main__":
    main()
