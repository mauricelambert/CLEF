![CLEF Logo](https://mauricelambert.github.io/info/bash/CLEF/logo_small.png "CLEF logo")

# CLEF

Collect Linux Evidence for Forensics.

## Description

This script collect evidence on a Linux system.

 - work on Debian-Based Linux Distributions
 - work on RedHat-Based Linux Distributions
 - work on minimal systems like containers (tested on docker)
 - work offline, in chroot or other method to isolate your Linux

## Requirements

This package require:

 - bash (version >= 4)
 - basic commands (cat, cp find, grep, awk...)
 - root privileges

## Installation

```bash
git clone https://github.com/mauricelambert/CLEF.git
```

## Usages

```bash
# Help
bash CLEF.sh -h
bash CLEF.sh --help

# Full collect
bash CLEF.sh
# OR
chmod +x CLEF.sh
./CLEF.sh

# Fast mode
bash CLEF.sh -f
bash CLEF.sh --fast

# No color mode
bash CLEF.sh -c
bash CLEF.sh --no-color

# No logs
bash CLEF.sh -l
bash CLEF.sh --no-logs

# No debug (interactive mode for debugging)
bash CLEF.sh -d
bash CLEF.sh --no-debug
```

## Help

```text
~# bash CLEF --help
Description: This script collects maximum evidence for forensic investigations.
USAGES: CLEF.sh [-h] [-c] [-d] [-l] [-f]
         -h/--help: this help message
         -c/--no-color: disabled colors (useful for output redirection)
         -d/--no-debug: disabled breakpoints (interactive mode for debugging)
         -l/--no-logs: no logs
         -f/--fast: fast mode (no files analysis and reporting)
```

## Screens

![CLEF running on debian-based system](https://mauricelambert.github.io/info/bash/CLEF/debian_run.PNG "CLEF running on debian-based system")
![CLEF running on minimal RedHat-based system](https://mauricelambert.github.io/info/bash/CLEF/minimal_centos_run.PNG "CLEF running on minimal RedHat-based system")
![CLEF running on docker container](https://mauricelambert.github.io/info/bash/CLEF/docker_run.PNG "CLEF running on docker container")

## Logo

![CLEF Logo](https://mauricelambert.github.io/info/bash/CLEF/logo.png "CLEF logo")

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
