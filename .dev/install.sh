#!/bin/bash - 
#===============================================================================
#
#          FILE: install.sh
# 
#         USAGE: ./install.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Francesco Emanuel Bennici (l0nax), benniciemanuel78@gmail.com
#  ORGANIZATION: FABMation GmbH
#       CREATED: 08/11/2020 11:47:27 AM
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
set -x

helm plugin remove whatup

make build
SKIP_BIN_INSTALL=1 helm plugin install $GOPATH/src/github.com/fabmation-gmbh/helm-whatup
