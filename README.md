# Helm Whatup

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](/LICENSE.md)
[![Maintainability](https://api.codeclimate.com/v1/badges/ec4254803f465c1c8a58/maintainability)](https://codeclimate.com/github/fabmation-gmbh/helm-whatup/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/ec4254803f465c1c8a58/test_coverage)](https://codeclimate.com/github/fabmation-gmbh/helm-whatup/test_coverage)
[![Go Report Card](https://goreportcard.com/badge/github.com/fabmation-gmbh/helm-whatup)](https://goreportcard.com/report/github.com/fabmation-gmbh/helm-whatup)
[![Build Status](https://travis-ci.org/fabmation-gmbh/helm-whatup.svg?branch=master)](https://travis-ci.org/fabmation-gmbh/helm-whatup)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a6cb2c603e46476fbc68dcfc767d10ea)](https://www.codacy.com/app/benniciemanuel78/helm-whatup?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fabmation-gmbh/helm-whatup&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3007/badge)](https://bestpractices.coreinfrastructure.org/projects/3007)

[![Latest Release](https://github-basic-badges.herokuapp.com/release/fabmation-gmbh/helm-whatup.svg)]()
[![Latest Release Downloads](https://img.shields.io/github/downloads/fabmation-gmbh/helm-whatup/latest/total?style=flat-square)]()
[![All Downloads](https://img.shields.io/github/downloads/fabmation-gmbh/helm-whatup/total?style=flat-square)]()

This Repo is a fork of [bacongobbler/helm-whatup][], because the original project is no longer actively further developed.

This is a Helm plugin to help users determine if there's an update available for their installed charts.
It works by reading your locally cached index files from the chart repositories (via `helm repo update`) and checking
the version against the latest deployed version of your charts in the Kubernetes cluster.

## Support

| `whatup` Version | Supported helm version |
|------------------|------------------------|
| 0.2.x            | 2.x                    |
| >= 0.3.x         | 3.x                    |

_NOTE: If you use a helm v3 Client you need to install the latest `whatup` Version!_

## Usage

```bash
helm repo update
helm whatup
```

## Example

Example output of `helm whatup`:

```bash
NAME                       	NAMESPACE	INSTALLED VERSION	LATEST VERSION	CHART
atlassian-confluence-server	devops   	1.0.4            	1.0.5         	atlassian-confluence-server
atlassian-crucible         	devops   	0.1.1            	0.1.3         	atlassian-crucible
atlassian-jira-software    	devops   	0.3.10           	0.3.11        	atlassian-jira-software
confluence-mysql           	devops   	1.4.0            	1.6.2         	mysql
fileshare                  	devops   	1.7.0            	1.9.1         	nextcloud
fileshare-postgres         	devops   	6.2.1            	8.1.2         	postgresql
```

## Install

```bash
helm plugin install https://github.com/fabmation-gmbh/helm-whatup
```

The above will fetch the latest binary release of `helm whatup` and install it.


### Developer (From Source) Install

If you would like to handle the build yourself, instead of fetching a binary, this is how recommend doing it.

First, set up your environment:

- You need to have [Go](http://golang.org) installed. Make sure to set `$GOPATH`

Clone this repo into your `$GOPATH` using git.

```bash
mkdir $GOPATH/src/github.com/fabmation-gmbh
cd $GOPATH/src/github.com/fabmation-gmbh
git clone https://github.com/fabmation-gmbh/helm-whatup
```

Then run the following to get running.

```bash
cd helm-whatup
make bootstrap build
SKIP_BIN_INSTALL=1 helm plugin install $GOPATH/src/github.com/fabmation-gmbh/helm-whatup
```

That last command will skip fetching the binary install and use the one you
built.




<!-- LINKS -->
[bacongobbler/helm-whatup]: https://github.com/bacongobbler/helm-whatup
