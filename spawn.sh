#!/bin/bash

# safety-pin
sleep 5

# 00. initial setup
export SU_USR=$1
export SU_UID=$2
export SU_GID=$3
export EXPORTMODE="WETRUN"
export SRCENVNAME=$4
#export DSTENVNAME=$5
#export WETRUNARGS=$6
#export WETRUNLOGF=$7

export K8S_JOB_NAME="conda-workflow"
export K8S_JOB_POSTFIX=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1)
export K8S_JOB_COUNTS=3
export K8S_JOB_APPGROUP="$K8S_JOB_NAME-$K8S_JOB_POSTFIX"
IFS_BACKUP=$IFS
IFS_NL=$'\n'
# using ASCII unit separator as delimiter
DLM=$'\037'
DQO='"'

echo "${SU_USR} - ${SU_UID} - ${SU_GID}"
echo "${K8S_JOB_APPGROUP}"

SSH_CRED_NAME="id_ed25519_${K8S_JOB_APPGROUP}"
ssh-keygen -q -t ed25519 -N '' -C "${SU_USR}@${K8S_JOB_APPGROUP}" -f "./${SSH_CRED_NAME}";
SSH_CRED_PRV=$(cat "./${SSH_CRED_NAME}")
SSH_CRED_PUB=$(cat "./${SSH_CRED_NAME}.pub")
echo "----------"
echo "${SSH_CRED_PUB}"
echo "----------"
echo "${SSH_CRED_PRV}"
echo "----------"
rm -f "./${SSH_CRED_NAME}" "./${SSH_CRED_NAME}.pub"

export BASE_YAML="job-condaenv-exporter-xo-cuda10_0.yaml"


K8S_JOB_APPNAME="${K8S_JOB_APPGROUP}-leader"

function launch_yaml() {

  K8S_JOB_APPNAME="${1}-${2}"
  K8S_JOB_APPGROUP="${1}"
  WETRUNARGS="${3}"

  sed -e "s${DLM}\$NB_USER${DLM}${DQO}${SU_USR}${DQO}${DLM}g;" \
      -e "s${DLM}\$SU_USR_HOME${DLM}${SU_USR}${DLM}g;" \
      -e "s${DLM}\$NB_UID${DLM}${DQO}${SU_UID}${DQO}${DLM}g;" \
      -e "s${DLM}\$NB_GID${DLM}${DQO}${SU_GID}${DQO}${DLM}g;" \
      -e "s${DLM}\$EXPORTMODE${DLM}${DQO}${EXPORTMODE}${DQO}${DLM}g;" \
      -e "s${DLM}\$SRCENVNAME${DLM}${DQO}${SRCENVNAME}${DQO}${DLM}g;" \
      -e "s${DLM}\$DSTENVNAME${DLM}${DQO}${DSTENVNAME}${DQO}${DLM}g;" \
      -e "s${DLM}\$WETRUNARGS${DLM}${DQO}${WETRUNARGS}${DQO}${DLM}g;" \
      -e "s${DLM}\$WETRUNLOGF${DLM}${DQO}${WETRUNLOGF}${DQO}${DLM}g;" \
      -e "s${DLM}\$K8S_JOB_APPNAME${DLM}${K8S_JOB_APPNAME}${DLM}g;" \
      -e "s${DLM}\$K8S_JOB_APPGROUP${DLM}${K8S_JOB_APPGROUP}${DLM}g;" \
    $BASE_YAML | kubectl apply -f -
#    $BASE_YAML
}

launch_yaml "${K8S_JOB_APPGROUP}" "leader" "/bin/sleep infinity"
echo "----------"
launch_yaml "${K8S_JOB_APPGROUP}" "worker1" "/bin/sleep infinity"
echo "----------"
launch_yaml "${K8S_JOB_APPGROUP}" "worker2" "/bin/sleep infinity"
echo "----------"

# 01b. check job 01 status
for (( ; ; ))
do
  CHK_ALL_RUNNING=true
  K8S_PODS_LIST=$(kubectl get pods -o wide -l appgroup=$K8S_JOB_APPGROUP | tail -n +2 | tr -s ' ')

  #NUM_PODS=$(echo "$K8S_PODS_LIST" | wc -l)
  #if [[ $NUM_PODS == "$K8S_JOB_COUNTS" ]]
  #then true;
  #else continue;
  #fi

  IFS=$IFS_NL
  for K8S_POD_INST_ID in $K8S_PODS_LIST
  do
    CHK_POD_STATE=$(echo "$K8S_POD_INST_ID" | cut -d ' ' -f3 | tr '[:upper:]' '[:lower:]')
    if [[ $CHK_POD_STATE == "running" ]]
    then continue;
    else CHK_ALL_RUNNING=false;break;
    fi
  done
  IFS=$IFS_BACKUP

  if [[ $CHK_ALL_RUNNING == true ]]
  then break;
  else echo "CHK_ALL_RUNNING? $CHK_ALL_RUNNING";sleep 1;continue;
  fi
done

# 01c. set hostnames
K8S_JOB_PODS_HOSTS=$(kubectl get pods -o wide -l appgroup=$K8S_JOB_APPGROUP | tail -n +2 | tr -s ' ' | cut -d' ' -f1,6)
K8S_JOB_POD_LEADER=$(kubectl get pods -o wide -l appgroup=$K8S_JOB_APPGROUP | tail -n +2 | tr -s ' ' | grep leader | cut -d' ' -f1)
K8S_JOB_PODS_HOSTFILE=$(kubectl get pods -o wide -l appgroup=$K8S_JOB_APPGROUP | tail -n +2 | tr -s ' ' | cut -d' ' -f1)

IFS=$IFS_NL
for K8S_POD_INST_ID in $K8S_JOB_PODS_HOSTS
do
  K8S_POD_INST_TARGET=$(echo "$K8S_POD_INST_ID" | cut -d' ' -f1)
  K8S_PODS_HOSTSFILE=$(echo "$K8S_JOB_PODS_HOSTS" | gawk -v appgroup=$K8S_JOB_APPGROUP '{match($1,appgroup"-(.*)-(.*)",arr);print $2"\t"arr[1]"\t"$1;}')
  #echo "working HOSTSFILE on $K8S_POD_INST_TARGET ..."

  kubectl exec -it $K8S_POD_INST_TARGET -- bash -c "cp /etc/hosts /etc/hosts.bkup;head -n -1 /etc/hosts.bkup >/etc/hosts;echo '$IFS_NL# MANUAL RESOLVE$IFS_NL$K8S_PODS_HOSTSFILE' >> /etc/hosts;echo '$K8S_JOB_PODS_HOSTFILE' >> /etc/hosts_mpirun;"
  kubectl exec -it $K8S_POD_INST_TARGET -- bash -c "mkdir -p /home/${SU_USR}/.ssh;echo '$SSH_CRED_PUB' >> /home/${SU_USR}/.ssh/authorized_keys;echo '$SSH_CRED_PUB' >> /home/${SU_USR}/.ssh/id_ed25519.pub;echo '$SSH_CRED_PRV' >> /home/${SU_USR}/.ssh/id_ed25519;echo 'Host *$IFS_NL    ServerAliveInterval 45$IFS_NL    ServerAliveCountMax 1920$IFS_NL    StrictHostKeyChecking no' >> /home/${SU_USR}/.ssh/config;chmod 600 /home/${SU_USR}/.ssh/*;chown -R $SU_UID:$SU_GID /home/${SU_USR}/.ssh;"
  #echo "----------"
  #echo
done
IFS=$IFS_BACKUP