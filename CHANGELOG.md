# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).


## 0.5.3 (2021-02-02)

### Other (1 change)
- Improve search of source repository


## 0.5.2 (2021-02-01)

### Fixed (1 change)
- Fix showing incorrect App Version in multi-repo table view


## 0.5.1 (2021-02-01)

### Changed (1 change)
- Print warning messages to /dev/stderr

### Fixed (2 changes)
- Fix `[[: not found` error in `install-binary.sh` script
- Fix showing repos serving depreacted charts if `--ignore-deprecation` is set to `true` ([#36 (comment 768978347)](https://github.com/fabmation-gmbh/helm-whatup/issues/36\#issuecomment-768978347))


## 0.5.0 (2021-01-27)

### Added (5 changes)
- Add '--ignore-deprecation' flag to allow ignoring Charts marked as "deprecated" ([#35](https://github.com/fabmation-gmbh/helm-whatup/issues/35))
- Add 'HELM_WHATUP_BETA_FEATURES' environment variable to toggle beta features in this plugin
- Add new row/field 'REPOSITORY' to output to show the name of the Chart repository containing the newer version.
- Colorize source repository in multi-repository table view ([#37](https://github.com/fabmation-gmbh/helm-whatup/issues/37))
- Print 'installed app version' in _table view_ when multiple repositories are providing the chart ([#36](https://github.com/fabmation-gmbh/helm-whatup/issues/36); [#36 (comment 768345618)](https://github.com/fabmation-gmbh/helm-whatup/issues/36\#issuecomment-768345618))

### Changed (1 change)
- Print seperator in 'table' output mode by the length of the current terminal ([#37](https://github.com/fabmation-gmbh/helm-whatup/issues/37))

### Other (2 changes)
- Fix typo in help page ([#37](https://github.com/fabmation-gmbh/helm-whatup/issues/37))
- Use '/bin/sh' instead of '/bin/bash' in the install script ([#34](https://github.com/fabmation-gmbh/helm-whatup/issues/34))


## 0.4.3 (2020-10-26)

### Fixed (1 change)
- Fix JSON/YAML output when multiple repositories do provide the chart ([#33](https://github.com/fabmation-gmbh/helm-whatup/issues/33))


## 0.4.2 (2020-09-01)

### Fixed (1 change)
- Print version information when '--version' is set


## 0.4.1 (2020-08-12)

### Changed (1 change)
- Enable 'ignore-repo' flag default ([#25](https://github.com/fabmation-gmbh/helm-whatup/issues/25))


## 0.4.0 (2020-08-12)

### Added (1 change)
- Add environment variable mapping for the '--ignore-repo' and '--deprecation-notice' flags

### Fixed (2 changes)
- Fix 'multiple repos with same charts' bug [#21]
- Link binaries statically to prevent 'no such file or directory' crashes ([#26](https://github.com/fabmation-gmbh/helm-whatup/issues/26))


## 0.3.2 (2019-12-17)

### Added (1 change)
- Add 'ignore-repo' Flag ([8af200d0a5b5e30e9eb06135e07289572710b7f2](https://github.com/helm/helm/commit/8af200d0a5b5e30e9eb06135e07289572710b7f2))


## 0.3.1 (2019-12-11)

### Fixed (1 change)
- Fix 'no Auth Provider found' Error [#12](https://github.com/fabmation-gmbh/helm-whatup/issues/12)


## 0.3.0 (2019-12-04)

### Added (1 change)
- Add support for helm v3 Client ([#11](https://github.com/fabmation-gmbh/helm-whatup/issues/11))

### Fixed (1 change)
- Add check for unset HELM_HOME Env Variable to the install Script ([#10](https://github.com/fabmation-gmbh/helm-whatup/issues/10))


## 0.2.0 (2019-07-25)

### Added (2 changes)
- Add TLS Support ([#1](https://github.com/fabmation-gmbh/helm-whatup/issues/1), [bacongobbler/helm-whatup#6](https://github.com/bacongobbler/helm-whatup/issues/6))
- Add _table_ Output Format ([#3](https://github.com/fabmation-gmbh/helm-whatup/issues/3))

