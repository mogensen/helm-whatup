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
set -x

VERSION="${1}"

######################

## 1) Create branch
git checkout develop
git checkout -b "release/${VERSION}"

## 2) Generate CHANGELOG.md
changelog release "${VERSION}"
git add CHANGELOG.md .changelogs
git commit -m "Generate CHANGELOG.md for ${VERSION}"

## 3) Bump plugin version
sed -i "s;^version:.*;version: \"$(echo -n ${VERSION} | tr -d 'v')\";g" plugin.yaml
git add plugin.yaml
git commit -m "Bump plugin version to ${VERSION}"

## 4) Create tag and merge
git tag -a -s "${VERSION}" -m "${VERSION}"
git checkout master
git merge --no-ff "release/${VERSION}"
git branch --delete "release/${VERSION}"

## 5) Push and clean up env
git push
git checkout develop
git rebase master
git push
git push --tag
