# k8s-workflow-distpara

---

# how-to-run:

```console
$ python spawn.py $SU_USR $SU_UID $SU_GID $SRCENVNAME $HOOKCMD $LOGFILE
```

* **SU_USR**: username of subtituting user
* **SU_UID**: uid (user-id) of subtituting user
* **SU_GID**: gid (group-id) of subtituting user
* **SRCENVNAME**: source condaenv name
* **DSTENVNAME**: destination condaenv name (for environment export)
* **HOOKCMD**: **"/bin/sleep infinity"**
* **LOGFILE**: destination for logfile, currently not used

##example:

```console
$ python spawn.py xo 606200001 606300000 py36tf114hvdgpu "/bin/sleep infinity" /dev/null
```

# bare command line in `spawn.py` (only for reference)

```console
mpirun -np 3 --hostfile /etc/hostfile -x LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libhwloc.so.5:/usr/lib/x86_64-linux-gnu/libjemalloc.so bash -c 'eval "$(/opt/conda/bin/conda shell.bash hook)";conda activate py36tf114hvdgpu;python workspace/horovod_test/horovod_tensorflow_mnist_0_18_2.py;'; mpirun -np 2 --hostfile /etc/hostfile_workers -x LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libhwloc.so.5:/usr/lib/x86_64-linux-gnu/libjemalloc.so bash -c 'eval "$(/opt/conda/bin/conda shell.bash hook)";conda activate py36tf114hvdgpu;kill -SIGTERM $(cat /var/run/wetrun.pid);'; kill -SIGTERM $(cat /var/run/wetrun.pid);
```

---
~~# image type A:~~

~~horovod/horovod:0.18.1-tf1.14.0-torch1.2.0-mxnet1.5.0-py3.6~~

