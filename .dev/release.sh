#!/bin/bash - 
#===============================================================================
#
#          FILE: release.sh
#
#         USAGE: ./release.sh <version>
#
#   DESCRIPTION: This script executes all required commands to release a new version of this plugin.
#                It will generate the CHANGELOG.md, tag, commit and push all those changes.
#
#       OPTIONS: git, sed, changelog-go
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Francesco Emanuel Bennici (l0nax), benniciemanuel78@gmail.com
#  ORGANIZATION: FABMation GmbH
#       CREATED: 09/01/20 13:43:33
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
set -e  # exit/ stop on error

x() {
    echo "+ ${@}"
    ${@}
}

VERSION="v"

######################

## 1) Create branch
x git checkout develop
x git checkout -b "release/${VERSION}"

## 2) Generate CHANGELOG.md
x changelog release "${VERSION}"
x git add CHANGELOG.md .changelogs
x git commit -m "Generate CHANGELOG.md for ${VERSION}"

## 3) Bump plugin version
x sed -i "s;^version:;version: \"(echo -n ${VERSION} | tr -d 'v')\"" plugin.yaml
x git add plugin.yaml
x git commit -m "Bump plugin version to ${VERSION}"

## 4) Create tag and merge
x git tag -a -s "${VERSION}" -m "${VERSION}"
x git checkout master
x git merge --no-ff "release/${VERSION}"
x git branch --delete "release/${VERSION}"

## 5) Push and clean up env
x git push
x git checkout develop
x git rebase master
x git push
x git push --tag
