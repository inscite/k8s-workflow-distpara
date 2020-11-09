#!/bin/bash

# Copyright (c) 2020 Seungkyun Hong. <nah@kakao.com>
# Distributed under the terms of the 3-Clause BSD License.

# condaenv-exporter launcher
# req. container: dataon.kr/condaenv-exporter:0.2

export SU_USR=$1
export SU_UID=$2
export SU_GID=$3
export EXPORTMODE=$4
export SRCENVNAME=$5
export DSTENVNAME=$6
export WETRUNARGS=$7
export WETRUNLOGF=$8

export BASE_YAML="job-condaenv-exporter-xo-cuda10_0.yaml"

# using ASCII unit separator as delimiter
DLM=$'\037'
DQO='"'

sed -e "s${DLM}\$NB_USER${DLM}${DQO}${SU_USR}${DQO}${DLM}g;" \
    -e "s${DLM}\$SU_USR_HOME${DLM}${SU_USR}${DLM}g;" \
    -e "s${DLM}\$NB_UID${DLM}${DQO}${SU_UID}${DQO}${DLM}g;" \
    -e "s${DLM}\$NB_GID${DLM}${DQO}${SU_GID}${DQO}${DLM}g;" \
    -e "s${DLM}\$EXPORTMODE${DLM}${DQO}${EXPORTMODE}${DQO}${DLM}g;" \
    -e "s${DLM}\$SRCENVNAME${DLM}${DQO}${SRCENVNAME}${DQO}${DLM}g;" \
    -e "s${DLM}\$DSTENVNAME${DLM}${DQO}${DSTENVNAME}${DQO}${DLM}g;" \
    -e "s${DLM}\$WETRUNARGS${DLM}${DQO}${WETRUNARGS}${DQO}${DLM}g;" \
    -e "s${DLM}\$WETRUNLOGF${DLM}${DQO}${WETRUNLOGF}${DQO}${DLM}g;" \
    $BASE_YAML | kubectl apply -f -
