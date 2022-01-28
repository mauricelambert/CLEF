#!/usr/bin/env bash

###################
#    This script collects maximum evidence for forensics (investigation) on Linux.
#    Copyright (C) 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

#
# This script collect evidence on a Linux system (Debian based, RedHat based and others).
# This script work on minimal systems like containers (tested on docker).
# This script work offline, in chroot or other method to isolate your Linux.
#

SHELL=${_}                                     # Get the shell path used to run this script
DEBUG=1                                        # Active breakpoint
COLOR=1                                        # Active color
LOG_LEVEL=10                                   # Mode debug
FILENAME="${0##*/}"                            # "$(basename \"${0}\")"
DATE="$(date +'%Y%m%d_%H%M%S')"                # Date in filename format
DIRNAME="${FILENAME%.*}_${DATE}"               # Report directory name
LAUNCH_PWD=$(pwd)                              # Get the current directory
LOG_FILE="${LAUNCH_PWD}/${DIRNAME}_LOG.csv"    # Log filename (logs are in CSV format)
COMMAND_FILE="file"                            # Command file does not exists on minimal OS
TOTAL_FILE=0
ONE_POURCENT=0
_ADD=1
POURCENT=0
STDOUT="/dev/stdout"

VERSION="0.0.2"
AUTHOR='Maurice LAMBERT'
DESCRIPTION='This script collects maximum evidence for forensic investigations.'
COPYRIGHT='
CLEF (Collect Linux Evidence for Forensics)  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
'

declare -A show_info_actions=(
    [OK]="\x1b[32m[+]"
    [NOK]="\x1b[33m[-]"
    [ERROR]="\x1b[31m[!]"
    [INFO]="\x1b[34m[*]"
    [TODO]="\x1b[35m[#]"
    [ASK]="\x1b[36m[?]"
)

declare -A LOG_LEVELS=(
    [10]="DEBUG    (10)"
    [20]="INFO     (20)"
    [30]="WARNING  (30)"
    [40]="ERROR    (40)"
    [50]="CRITICAL (50)"
)

set -e                                         # Stop process on errors

function to_CSV() {
    #
    # @desc   :: This function prints a CSV syntax from arguments
    # @params :: string[] $@ - each string of array are columns
    #

    local string=""

    while [[ $# > 0 ]]; do
        string+=",\"${1//\"/\'}\""
        shift
    done

    echo "${string:1}"  # first character is ","
    return 0
}

function logging() {
    #
    # @desc   :: This function prints colored informations
    # @param  :: string $1 - [REQUIRED] Log message
    # @param  :: string $2 - [REQUIRED] Log level
    # @param  :: string $3 - Localization (caller: "<line> <function> <filename>")
    #

    local log_message="${1}"
    local level="${2}"
    local localization="${3}"

    if [[ $level -lt $LOG_LEVEL ]]; then
        return 0
    else
        level="${LOG_LEVELS[${level}]}"
    fi

    if [[ -z "${localization}" ]]; then
        localization=$(caller)
    fi

    to_CSV "$(date +'%Y-%m-%d %T')" "${level}" "${FILENAME}" "${$}" "${SHELL}" "${localization}" "${log_message}" >> "${LOG_FILE}"
    return 0
}

function log_debug() {
    #
    # @desc   :: This function logs debug messages
    # @param  :: string $1 - [REQUIRED] Log message
    #

    logging "${1}" 10 "$(caller)"
    return 0
}

function log_info() {
    #
    # @desc   :: This function logs debug messages
    # @param  :: string $1 - [REQUIRED] Log message
    #

    logging "${1}" 20 "$(caller)"
    return 0
}

function log_warning() {
    #
    # @desc   :: This function logs debug messages
    # @param  :: string $1 - [REQUIRED] Log message
    #

    logging "${1}" 30 "$(caller)"
    return 0
}

function log_error() {
    #
    # @desc   :: This function logs debug messages
    # @param  :: string $1 - [REQUIRED] Log message
    #

    logging "${1}" 40 "$(caller)"
    return 0
}

function log_critical() {
    #
    # @desc   :: This function logs debug messages
    # @param  :: string $1 - [REQUIRED] Log message
    #

    logging "${1}" 50 "$(caller)"
    return 0
}

# Init CSV logging
to_CSV "Date Time" "Log Level" "Filename" "PID" "Shell" "Localization" "Log Message" > "${LOG_FILE}"
log_debug "Logger is configured"

function show_info() {
    #
    # @desc   :: This function prints colored informations
    # @param  :: string $1 - [REQUIRED] Information to print
    # @param  :: string $2 - Default: OK, {OK,NOK,ERROR,INFO,TODO,ASK} -> Type of information
    # @param  :: int    $3 - The percentage of items performed from the current task
    # @param  :: string $4 - Start of the print
    # @param  :: string $5 - End of the print
    # @param  :: string $6 - Default: 0, {0,1} -> Pourcent on the same line
    #

    local string="${1}"
    local state="${2}"
    local pourcent="${3}"
    local start="\x1b[K${4}"
    local end="${5}"

    if [[ -z "${state}" ]]; then
        state=${show_info_actions["OK"]}
    else
        state=${show_info_actions["${state}"]}
    fi

    if [[ -z "${end}" ]]; then
        end="\n"
    fi

    if [[ -n "${pourcent}" ]]; then

        progressbar=" |"

        for i in {1..20}
        do
            if [[ ${pourcent} -ge $((i * 5)) ]]
            then
                progressbar+="\xe2\x96\x88"
            else
                progressbar+=" "
            fi
        done

        progressbar+="|"

        if [[ $COLOR -eq 0 ]]; then
            pourcent_state=${show_info_actions["INFO"]:8}
            color_end=""
        else
            pourcent_state=${show_info_actions["INFO"]}
            color_end="\x1b[0m"
        fi

        if [[ "${6}" -eq 0 ]]; then
            end="${end}${pourcent_state} ${pourcent}%${progressbar}${color_end}\r"
        else
            end=" ${pourcent_state:0:-3} ${pourcent}%${progressbar}${color_end}${end}"
        fi
    fi

    if [[ $COLOR -eq 0 ]]; then
        echo -en "${start}${state:8} ${string}${end}\x1b[F" > "${STDOUT}"
    else
        echo -en "${start}${state} ${string}\x1b[0m${end}\x1b[F" > "${STDOUT}"
    fi
}

function BREAKPOINT() {
    #
    # @desc   :: This function implements a breakpoint for debugging bash script
    # @params :: string[] $@ - [REQUIRED] The name of the breakpoint
    #

    if [[ $DEBUG -eq 0 ]]; then
        return 1
    fi

    local BREAKPOINT_NAME="${@}"
    show_info "Enter breakpoint $BREAKPOINT_NAME" "INFO" $POURCENT
    set +e  # custom exit code
    /bin/bash
    local BREAKPOINT_EXIT_CODE=$?
    set -e
    
    if [[ $BREAKPOINT_EXIT_CODE -eq 0 ]]; then
        show_info "Continue after breakpoint $BREAKPOINT_NAME" "INFO" $POURCENT
        return 0
    else
        show_info "Terminate after breakpoint $BREAKPOINT_NAME" "ERROR" $POURCENT
        trap - EXIT
        exit $BREAKPOINT_EXIT_CODE
    fi
}

function get_commands() {
    #
    # @desc   :: This function saves all commands (and aliases)
    #

    show_info "Processing commands and aliases..." "INFO" $POURCENT
    local dir="commands"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    log_debug "Get commands..."
    set +e  # Invalid path raise an error
    commands=`echo -n $PATH | xargs -d : -I {} find {} -maxdepth 1 -executable \( -type f -o -type l \) -printf '%P\n' 2>error.txt`
    set -e

    log_debug "Get aliases..."
    local aliases=`alias | cut -d '=' -f 1`
    
    local output=$(echo "${commands[@]}"$'\n'"${aliases}" | sort -u)
    
    log_debug "Save commands and aliases..."
    echo "${output}" > commands_and_aliases.txt
    echo "${commands[@]}" > commands.txt
    echo "${aliases}" > aliases_name.txt
    echo "$(alias)" > aliases.txt

    log_debug "Set not installed commands with /bin/true..."
    if [[ ! "${commands[@]}" =~ $'\nfile\n' ]]; then
        log_warning "'File' command not found ... Some suspicious files will not be detected and the file type will not be present in the file report."
        show_info "'File' command not found ... Some suspicious files will not be detected and the file type will not be present in the file report." "NOK"
        COMMAND_FILE=/bin/true
    fi

    log_info "Commands and aliases are successfully saved."
    cd ..
    show_info "COLLECTED: commands and aliases" "OK" $POURCENT
    return 0
}

function get_files() {
    #
    # @desc   :: This function saves files (names, type, hash, metadata...)
    #

    show_info "Processing files..." "INFO" $POURCENT
    local dir="files"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    if [[ "${commands[@]}" =~ $'\nlsof\n' ]]; then
        log_debug "Use lsof command..."
        lsof +L > "lsof_L.txt" 2>>errors.txt
    fi

    log_debug "Init files.csv file"
    to_CSV path filename permissions user group size type birthdate accessdate modificationdate statusdate hash type > "files.csv"

    log_info "Start the file processing, this step take a long time..."
    shopt -s globstar

    local counter=1
    local counter_total=1
    for filename in /**; do 
        # path filename permissions user group size type birthdate accessdate modificationdate statusdate hash type

        if [[ -f "${filename}" && ! -h "${filename}" && "/proc/" != "${filename:0:6}" && "/sys/" != "${filename:0:5}" ]]; then
            local _hash=$(md5sum "${filename}" | grep -oE "^[0-9a-f]+")
            to_CSV "${filename}" "$(stat -c '%N %A %U %G %s %F %w %x %y %z' "${filename}")" "${_hash}" "$($COMMAND_FILE ${filename} 2>/dev/null)" >> "files.csv"
            ((counter++))
            ((counter_total++))

            if [[ ${counter} -ge  ${ONE_POURCENT} ]]; then
                log_debug "Add one % of collection..."
                local counter=1                                    # a=0 && ((a++)) -> exit code == 1
                ((POURCENT++))
                show_info "${counter_total} / ${TOTAL_FILE} files are processed" "OK" "${POURCENT}" "" "\r" "1"
            fi
        elif [[ -e "${filename}" ]]; then
            to_CSV "${filename}" "$(stat -c '%N %A %U %G %s %F %w %x %y %z' "${filename}")" "" "$($COMMAND_FILE ${filename} 2>/dev/null)" >> "files.csv"
        fi
    done

    shopt -u globstar
    log_info "Files are processed."

    log_info "Files are successfully saved."
    cd ..
    show_info "COLLECTED: files" "OK" $POURCENT
    return 0
}

function get_regex_match() {
    #
    # @desc   :: This function saves regex matchs in all files
    #

    show_info "Processing regex match..." "INFO" $POURCENT
    local dir="regex"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    log_info "Start the regex processing, this step take a long time..."
    shopt -s globstar

    local counter=1
    local counter_total=1
    for filename in /**; do

        if [[ -f "${filename}" && ! -h "${filename}" && "/proc/" != "${filename:0:6}" && "/sys/" != "${filename:0:5}" ]]; then

            data=""
            while IFS= read -r -d '' substring || [[ $substring ]]; do
                data+="$substring"
            done < "${filename}"
            
            echo "${data}" | grep -oE '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | awk ' { print $0 } ' >> ipv4.txt
            echo "${data}" | grep -oP '(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}' | awk ' { print $0 } ' >> domain.txt
            echo "${data}" | grep -oP '((http|https)://)(www.)?[a-zA-Z0-9@:%._\+~#?&//=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%._\+~#?&//=]*)' | awk ' { print $0 } '  >> urls.txt
            echo "${data}" | grep -oP '(?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?' | awk ' { print $0 } ' >> base64.txt
            echo "${data}" | grep -oP '(([^<>()[\]\.,;:\s@"]+(\.[^<>()[\]\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))' | awk ' { print $0 } ' >> email.txt
            echo "${data}" | grep -oP '\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?' | awk ' { print $0 } ' >> uuid.txt
            echo "${data}" | grep -oP '(%(25)?[0-9A-Fa-f]{2}){5,}' | awk ' { print $0 } ' >> urlencode.txt
            echo "${filename}" | grep -oP '\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?' | awk ' { print $0 } ' >> uuid.txt
            ((counter++))
            ((counter_total++))

            if [[ ${counter} -ge ${ONE_POURCENT} ]]; then
                log_debug "Add one % of collection..."
                local counter=1                                    # a=0 && ((a++)) -> exit code == 1
                ((POURCENT++))
                show_info "${counter_total} / ${TOTAL_FILE} files are processed" "OK" "${POURCENT}" "" "\r" "1"
            fi
        fi
    done

    shopt -u globstar
    log_info "Regex are processed."

    log_info "Regex are successfully saved."
    cd ..
    show_info "COLLECTED: regex match" "OK" $POURCENT
    return 0
}

function get_environment_vars() {
    #
    # @desc   :: This function saves all installed environment variable and functions
    #

    show_info "Processing environment variables..." "INFO" $POURCENT
    local dir="environment_vars"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_env=(
        [printenv]="printenv"
        [export]="export"
        [env]="env"
        [declare]="declare -f"
        [set]="set -o posix"
    )

    for command in "${!_get_env[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_env[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    set > "set2.txt" 2>>errors.txt

    log_info "Environment variables are successfully saved."
    cd ..
    show_info "COLLECTED: environment variables" "OK" $POURCENT
    return 0
}

function get_modules() {
    #
    # @desc   :: This function saves loaded modules
    #

    show_info "Processing modules..." "INFO" $POURCENT
    local dir="modules"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_modules=(
        [lsmod]="lsmod"
        [cat]="cat /proc/modules"
    )

    for command in "${!_get_modules[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_modules[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\nlsmod\n' && "${commands[@]}" =~ $'\nmodprobe\n' ]]; then
        log_info "Detect 'lsmod' and 'modprobe' are installed."
        for module in $(lsmod | awk '$2 ~ /[0-9]+/ { print $1 }'); do
            modprobe --show-depends "${module}" >> "modprobe.txt" 2>>errors.txt
        done
    fi

    if [[ "${commands[@]}" =~ $'\nlsmod\n' && "${commands[@]}" =~ $'\nmodinfo\n' ]]; then
        log_info "Detect 'lsmod' and 'modinfo' are installed."
        for module in $(lsmod | awk '$2 ~ /[0-9]+/ { print $1 }'); do
            modinfo "${module}" >> "modinfo.txt" 2>>errors.txt
        done
    fi

    log_info "Modules are successfully saved."
    cd ..
    show_info "COLLECTED: modules" "OK" $POURCENT
    return 0
}

function get_system() {
    #
    # @desc   :: This function saves system
    #

    show_info "Processing system..." "INFO" $POURCENT
    local dir="system"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_system=(
        [cat]="cat /proc/version"
        [uname]="uname -a"
        [hostname]="hostname"
    )

    for command in "${!_get_system[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_system[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\nhostname\n' ]]; then
        hostname -I > ip.txt
    fi

    log_info "System state are successfully saved."
    cd ..
    show_info "COLLECTED: system" "OK" $POURCENT
    return 0
}

function get_disks() {
    #
    # @desc   :: This function saves disks state
    #

    show_info "Processing disks state..." "INFO" $POURCENT
    local dir="disks"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_disks=(
        [fdisk]="fdisk -l"
        [df]="df -h"
        [findmnt]="findmnt -a -A"
        [vgdisplay]="vgdisplay -v"
        [lvdisplay]="lvdisplay -v"
        [vgs]="vgs --all"
        [lvs]="lvs --all"
        [free]="free"
        [cat]="cat /proc/partitions"
    )

    for command in "${!_get_disks[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_disks[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
        log_info "Detect 'du' is installed."
        set +e  # permissions error on non existant files
        du -sh / > "du.txt" 2>>errors.txt
        set -e
    fi

    if [[ -e "/dev/mapper" ]]
    then
        ls -l /dev/mapper > "mapper.txt" 2>>errors.txt
    fi

    log_debug "Copy files fstab mtab..."
    copy_files "/etc/fstab"
    copy_files "/etc/mtab"

    log_info "Disks state are successfully saved."
    cd ..
    show_info "COLLECTED: disks" "OK" $POURCENT
    return 0
}

function get_packages() {
    #
    # @desc   :: This function saves all installed packages
    #

    show_info "Processing packages..." "INFO" $POURCENT
    local dir="packages"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_packages=(
        [pacman]="pacman -Q"
        [apk]="apk info -vv"
        [apt]="apt list --installed"
        [dpkg]="dpkg -l"
        [dpkg-query]="dpkg-query -l"
        [yum]="yum list installed"
        [dnf]="dnf list installed"
        [zypper]="zypper se --installed-only"
        [rpm]="rpm -qa"
        [snap]="snap list"
        [flatpak]="flatpak list --app"
    )

    for command in "${!_get_packages[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_packages[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    _get_packages=(
        [dpkg]="dpkg -V"
    )

    for command in "${!_get_packages[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_packages[$command]} > "${command}_verify.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\nrpm\n' ]]; then
        set +e  # -V raise an error
        rpm="rpm -Va"
        set -e
    fi

    log_info "Packages are successfully saved."
    cd ..
    show_info "COLLECTED: packages" "OK" $POURCENT
    return 0
}

function get_accounts() {
    #
    # @desc   :: This function saves users and groups
    #

    show_info "Processing accounts..." "INFO" $POURCENT
    local dir="accounts"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    log_debug "Copy account files..."
    copy_files /etc/passwd
    copy_files /etc/passwd-
    copy_files /etc/group
    copy_files /etc/group-
    copy_files /etc/shadow
    copy_files /etc/shadow-
    copy_files /etc/gshadow
    copy_files /etc/gshadow-

    log_debug "Use who command..."
    who -alpu > who.txt

    log_info "Accounts are successfully saved."
    cd ..
    show_info "COLLECTED: accounts" "OK" $POURCENT
    return 0
}

function get_process() {
    #
    # @desc   :: This function saves running process
    #

    show_info "Processing process..." "INFO" $POURCENT
    local dir="process"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_process=(
        [pstree]="pstree"
        [ps]="ps faux"
        [top]="top -H -b -n 1"
    )

    for command in "${!_get_process[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_process[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\nps\n' ]]; then
        ps -ewo "%p,%P,%x,%t,%u,%c,%a" > "ps2.txt"
    fi

    if [[ "${commands[@]}" =~ $'\ntop\n' ]]; then
        top -b -n 1 > "top2.txt"
    fi

    log_info "Process are successfully saved."
    cd ..
    show_info "COLLECTED: process" "OK" $POURCENT
    return 0
}

function get_services() {
    #
    # @desc   :: This function saves services
    #

    show_info "Processing services..." "INFO" $POURCENT
    local dir="services"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    if [[ "${commands[@]}" =~ $'\nfirewalld\n' ]]; then
        log_info "Detect 'firewalld' is installed."
        set +e  # return code -> 1
        firewalld
        set -e
    fi

    declare -A _get_services=(
        [systemctl]="systemctl list-units --all"
        [ls]="echo ""$(ls -la /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service 2>>/dev/null)"
        [service]="service --status-all"
        [firewall-cmd]="firewall-cmd --list-services"
        [sysv-rc-conf]="sysv-rc-conf -list"
        [chkconfig]="chkconfig --list"
    )

    shopt -s globstar
    for command in "${!_get_services[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_services[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done
    shopt -u globstar

    if [[ "${commands[@]}" =~ $'\nsystemctl\n' ]]; then
        log_debug "Use systemctl filters..."
        systemctl --type=service --state=failed > "systemctl_services_failed.txt" 2>>errors.txt
        systemctl --type=service --state=active > "systemctl_services_active.txt" 2>>errors.txt
        systemctl --type=service --state=running > "systemctl_services_running.txt" 2>>errors.txt
    fi

    if [[ "${commands[@]}" =~ $'\nls\n' ]]; then
        ls -l /etc/init.d/* > "ls_etc_initd.txt" 2>>errors.txt
    fi

    log_info "Services are successfully saved."
    cd ..
    show_info "COLLECTED: services" "OK" $POURCENT
    return 0
}

function get_opened_ports() {
    #
    # @desc   :: This function saves opened ports
    #

    show_info "Processing opened ports..." "INFO" $POURCENT
    local dir="ports"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    if [[ "${commands[@]}" =~ $'\nfirewalld\n' ]]; then
        log_info "Detect 'firewalld' is installed."
        set +e  # return code -> 1
        firewalld
        set -e
    fi

    declare -A _get_ports=(
        [ss]="ss --all"
        [netstat]="netstat -a"
        [lsof]="lsof -i -n -P"
    )

    for command in "${!_get_ports[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_ports[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    _get_ports[ss]="ss -lntu"
    _get_ports[netstat]="netstat -lntu"
    _get_ports[lsof]="lsof -i -n -P | awk ' \$0 ~ \"LISTEN\" { print \$0 } '"
    _get_ports["firewall-cmd"]="firewall-cmd --list-ports"

    for command in "${!_get_ports[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            eval "${_get_ports[$command]} > '${command}_listen_udp_tcp.txt' 2>>errors.txt"
        fi
    done

    log_info "Ports are successfully saved."
    cd ..
    show_info "COLLECTED: opened ports" "OK" $POURCENT
    return 0
}

function get_arp_cache() {
    #
    # @desc   :: This function saves arp cache
    #

    show_info "Processing arp cache..." "INFO" $POURCENT
    local dir="arp"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_arp=(
        [arp]="arp -a"
        [cat]="cat /proc/net/arp"
    )

    for command in "${!_get_arp[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_arp[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    log_info "Arp cache are successfully saved."
    cd ..
    show_info "COLLECTED: arp cache" "OK" $POURCENT
    return 0
}

function get_network_traffic() {
    #
    # @desc   :: This function saves network traffic statistics
    #

    show_info "Processing network traffic statistics..." "INFO" $POURCENT
    local dir="traffic"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_traffic=(
        [grep]="grep -H . /sys/class/net/*/statistics/rx_packets"
        [ip]="ip -s -s link"
        [ethtool]="ethtool -S {network}"
    )

    if [[ "${commands[@]}" =~ $'\nip\n' ]]; then
        _interfaces=$(ip addr show | awk ' $0 ~ /^[0-9]+:\s+\w+:/ { print $2 } ' ) # ls /sys/class/net
    else
        _interfaces=""
    fi

    for command in "${!_get_traffic[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."

            if [[ -n "${_interfaces}" && ${_get_traffic[$command]} =~ "{network}" ]]; then
                for _interface in ${_interfaces[@]}; do

                    if [[ "${_interface}" == "lo:" ]]; then continue; fi

                    _interface=${_interface/:/}
                    ${_get_traffic[$command]//"{network}"/"${_interface}"} > "${command}_${_interface}.txt" 2>>errors.txt
                done
            else
                ${_get_traffic[$command]} > "${command}.txt" 2>>errors.txt
            fi
        fi
    done

    log_info "Network traffic statistics are successfully saved."
    cd ..
    show_info "COLLECTED: network traffic statistics" "OK" $POURCENT
    return 0
}

function get_network_interfaces() {
    #
    # @desc   :: This function saves network interfaces
    #

    show_info "Processing network interfaces..." "INFO" $POURCENT
    local dir="interfaces"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_interfaces=(
        [ifconfig]="ifconfig -a"
        [iwconfig]="iwconfig"
        [ip]="ip addr"
        [cat]="cat /proc/net/dev"
        [netstat]="netstat -i"
        [nmcli]="nmcli device status"
        [lshw]="lshw -class network -short"
        [hwinfo]="hwinfo --short --network"
        [inxi]="inxi -N"
        [lspci]="lspci | awk ' tolower(\$0) ~ /network|ethernet|wireless|wi-fi/ { print \$0 } '"
    )

    for command in "${!_get_interfaces[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            eval "${_get_interfaces[$command]} > '${command}.txt' 2>>errors.txt"
        fi
    done

    log_debug "Copy hosts files..."
    if [[ "${commands[@]}" =~ $'\ncat\n' && -f "/etc/hosts" ]]; then
        cat /etc/hosts > "hosts.txt" 2>>errors.txt
    fi

    if [[ "${commands[@]}" =~ $'\ncat\n' && -f "hosts.allow.txt" ]]; then
        cat /etc/hosts.allow > "hosts.allow.txt" 2>>errors.txt
    fi

    if [[ "${commands[@]}" =~ $'\ncat\n' && -f "hosts.deny.txt" ]]; then
        cat /etc/hosts.deny > "hosts.deny.txt" 2>>errors.txt
    fi

    log_info "Interfaces are successfully saved."
    cd ..
    show_info "COLLECTED: process" "OK" $POURCENT
    return 0
}

function get_tasks() {
    #
    # @desc   :: This function saves scheduled tasks (servicse, cron, rc, .profile ...)
    #

    show_info "Processing scheduled tasks..." "INFO" $POURCENT
    local dir="tasks"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    shopt -s globstar

    declare -A files
        
    files[bashrc]="/etc/*bashrc* /home/*/.bashrc* /home/*/.bash_profile* /home/*/.profile* /home/*/.bash_login /root/.bashrc* /home/*/.profile* /root/.profile* /root/.bash_login"
    files[cron]="/etc/*cron**/* /etc/cron* /var/spool/**/cron*"
    files[service]="/etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service"
    files[rc]="/etc/rc*.d**/* /etc/rc.local*"

    for directory in "${!files[@]}"
    do
        mkdir "${directory}"
        for filename in ${files[$directory]}; do
            log_debug "Scheduled file: ${filename} is detected and save it..."
            copy_files "${filename}" "" "${directory}/"
        done
    done

    shopt -u globstar

    set +e # user without cron will raise an error
    cut -d: -f1 /etc/passwd | while read username
    do
        crontab -u "${username}" -l > "${username}_crontab.txt" 2>>errors.txt
    done
    set -e

    log_info "Scheduled tasks state are successfully saved."
    cd ..
    show_info "COLLECTED: scheduled tasks" "OK" $POURCENT
    return 0
}

function get_hardware() {
    #
    # @desc   :: This function saves hardware
    #

    show_info "Processing hardware..." "INFO" $POURCENT
    local dir="hardware"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_hardware=(
        [lspci]="lspci -kDq"
        [dmidecode]="dmidecode"
        [lscpu]="lscpu -a -p"
        [cat]="cat /proc/cpuinfo"
    )

    for command in "${!_get_hardware[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_hardware[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\nlscpu\n' ]]; then
        lscpu > "lscpu2.txt" 2>>errors.txt
    fi

    log_info "Hardware state are successfully saved."
    cd ..
    show_info "COLLECTED: hardware" "OK" $POURCENT
    return 0
}

function get_logs() {
    #
    # @desc   :: This function saves logs
    #

    show_info "Processing logs..." "INFO" $POURCENT
    local dir="logs"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_logs=(
        [last]="last -Faixw"
        [journalctl]="journalctl -x"
    )

    for command in "${!_get_logs[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_logs[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\njournalctl\n' ]]; then
        journalctl -k > "journalctl_k.txt"
    fi

    if [[ "${commands[@]}" =~ $'\ndmesg\n' ]]; then
        set +e     # docker -> dmesg: read kernel buffer failed: Operation not permitted
        dmesg -T > "dmesg.txt" 2>>errors.txt
        set -e
    fi

    shopt -s globstar

    declare -A files=(
        [apache_access]=/var/log/apache*/**access*
        [apache_error]=/var/log/apache*/**error*
        [boot]=/var/log/boot**
        [btmp]=/var/log/btmp**
        [wtmp]=/var/log/wtmp**
        [httpd_access]=/var/log/httpd/**access*
        [httpd_error]=/var/log/httpd/**error*
        [kern]=/var/log/kern**
        [mail]=/var/log/mail**
        [mariadb]=/var/log/mariadb/**
        [message]=/var/log/message**
        [mysql]=/var/log/mysql/**
        [nginx_access]=/var/log/nginx/**access*
        [nginx_error]=/var/log/nginx/**error*
        [secure]=/var/log/secure**
        [squid_access]=/var/log/squid/**access*
        [syslog]=/var/log/syslog**
    )

    for directory in "${!files[@]}"
    do
        mkdir "${directory}"
        for filename in ${files[$directory]}; do
            log_debug "Log file: ${filename} is detected and save it..."
            copy_files "${filename}" "" "${directory}/"
        done
    done

    shopt -u globstar

    log_info "Logs are successfully saved."
    cd ..
    show_info "COLLECTED: logs" "OK" $POURCENT
    return 0
}

function get_configurations() {
    #
    # @desc   :: This function saves configurations
    #

    show_info "Processing configurations..." "INFO" $POURCENT
    local dir="configurations"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    mkdir -p /run/sshd

    if [[ "${commands[@]}" =~ $'\nfirewalld\n' ]]; then
        log_info "Detect 'firewalld' is installed."
        set +e  # return code -> 1
        firewalld
        set -e
    fi

    declare -A _get_conf=(
        [iptables]="iptables -S"
        [nft]="sudo nft list tables"
        [firewalld-cmd]="firewall-cmd --list-all"
        [sshd]="sshd -T"
        [sysctl]="sysctl -a"
    )

    for command in "${!_get_conf[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_conf[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    shopt -s globstar

    declare -A files=(
        [apache]=/etc/apache*/*.conf
        [apt]=/etc/apt**/*.list*
        [apparmor]=/etc/apparmor*/*.conf
        [avahi]=/etc/avahi/*.conf
        [firewalld]=/etc/firewalld/*.conf
        [grub]=/boot/grub/grub.conf*
        [httpd]=/etc/httpd/*.conf
        [ipsec]="/etc/ipsec* /etc/ipsec**/*"
        [lighthttpd]=/etc/lighthttpd/*.conf
        [mariadb]=/etc/mariadb/*
        [modprobe]="/etc/modprobe.d/* /etc/modprobe.d/**/*"
        [mysql]=/etc/mysql/*
        [nftables]=/etc/nftables*
        [nginx]=/etc/nginx/*
        [ntp]=/etc/ntp*
        [pam]="/etc/pam* /etc/pam**/*"
        [postgresql]="/etc/postgresql*/* /etc/postgresql**/*"
        [resolv]=/etc/resolv*
        [rsyslog]="/etc/rsyslog* /etc/rsyslog**/*"
        [samba]=/etc/samba**/*
        [security]=/etc/security**/*
        [selinux]=/etc/selinux/*
        [snmp]=/etc/snmp/*
        [ssh]=/etc/ssh**/*
        [sudo]="/etc/sudo* /etc/sudo**/*"
        [sudoers]="/etc/sudoers* /etc/sudoers**/*"
        [sysctl]="/etc/sysctl* /etc/sysctl**/*"
        [yum]="/etc/yum.* /etc/yum**/*"
    )

    for directory in "${!files[@]}"
    do
        mkdir "${directory}"
        for filename in ${files[$directory]}; do
            log_debug "Configuration file: ${filename} is detected and save it..."
            copy_files "${filename}" "" "${directory}/"
        done
    done

    shopt -u globstar

    log_info "Configurations are successfully saved."
    cd ..
    show_info "COLLECTED: configurations" "OK" $POURCENT
    return 0
}

function get_webserverscripts() {
    #
    # @desc   :: This function saves web server scripts
    #

    show_info "Processing web server scripts..." "INFO" $POURCENT
    local dir="WebServerScripts"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    shopt -s globstar
    for filename in /var/www/**/*.py /var/www/**/*.php /var/www/**/*.js /var/www/**/*.rb /var/www/**/*.pl /var/www/**/*.cgi /var/www/**/*.sh /var/www/**/*.go /var/www/**/*.war; do
        log_debug "Web server scripts: ${filename} is detected and save it..."
        copy_files "${filename}"
    done
    shopt -u globstar

    log_info "Web server scripts state are successfully saved."
    cd ..
    show_info "COLLECTED: web server scripts" "OK" $POURCENT
    return 0
}

function get_histories() {
    #
    # @desc   :: This function saves histories
    #

    show_info "Processing histories..." "INFO" $POURCENT
    local dir="histories"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    for filename in /home/*/ /root/; do
        if [[ "${filename}" =~ "history" ]]; then
            log_debug "History: ${filename} is detected and save it..."
            copy_files "${filename}"
        fi
    done

    if [[ "${commands[@]}" =~ $'\nhistory\n' ]]; then
        history > "history.txt" 2>>errors.txt
    fi

    log_info "Histories are successfully saved."
    cd ..
    show_info "COLLECTED: histories" "OK" $POURCENT
    return 0
}

function get_suspicious() {
    #
    # @desc   :: This function saves suspicious files
    #

    show_info "Processing suspicious files..." "INFO" $POURCENT
    local dir="suspicious"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    log_info "Collect suspicious files (in /tmp with +x permissions)"
    find /tmp -type f -perm /+x | while read filename
    do 
        copy_files "${filename}"
        echo "${filename}: permissions is executable in /tmp folder (security risk)" >> report.txt
    done

    for filename in /tmp/**
    do 
        if [[ -n "$($COMMAND_FILE ${filename} | awk ' /(ELF|executable|PE32|shared object|script)/ { print $0 } ')" ]]; then
            copy_files "${filename}"
            echo "${filename}: is executable or script (type) in /tmp folder (security risk)" >> report.txt
        fi
    done

    log_info "Suspicious files state are successfully saved."
    cd ..
    show_info "COLLECTED: suspicious files" "OK" $POURCENT
    return 0
}

function get_states() {
    #
    # @desc   :: This function saves system state
    #

    show_info "Get states..." "INFO" $POURCENT
    local dir="states"
    mkdir "${dir}" && cd "${dir}"
    log_info "The ${dir} report directory is created and it is the new current directory"

    declare -A _get_conf=(
        [iostat]="iostat -t -N -x 1 2"
        [vmstat]="vmstat"
        [numastat]="numastat"
        [mpstat]="mpstat"
    )

    for command in "${!_get_conf[@]}"
    do
        if [[ "${commands[@]}" =~ $'\n'"${command}"$'\n' ]]; then
            log_info "Detect '${command}' is installed."
            ${_get_conf[$command]} > "${command}.txt" 2>>errors.txt
        fi
    done

    if [[ "${commands[@]}" =~ $'\nnfsstat\n' ]]; then
        log_info "Detect 'nfsstat' is installed."
        set +e
        nfsstat > "nfsstat.txt" 2>>errors.txt
        set -e
    fi

    local files=(/proc/interrupts /proc/meminfo /proc/buddyinfo /proc/slabinfo)

    for file in files
    do
        if [[ -e "${file}" ]]
        then
            cat "${file}" > "${file##*/}" 
        fi
    done

    log_info "System state is successfully saved."
    cd ..
    show_info "COLLECTED: state files" "OK" $POURCENT
    return 0
}

function copy_files() {
    #
    # @desc   :: This function copy files and directory
    # @param  :: string $1 - [REQUIRED] path (file or directory)
    # @param  :: string $2 - Default: file, {file, dir} -> type (file or directory)
    # @param  :: string $3 - Default: ./ -> directory (should be exists, don't forgot the last "/")
    # @param  :: string $4 - ID for recursive function, do not use it !
    #

    log_debug "copy_files: Get file type..."
    if [[ -z "${2}" ]]; then
        local type="file"
    else
        local type="${2}"
    fi

    log_debug "copy_files: Get directory..."
    if [[ -z "${3}" ]]; then
        local dir="./"
    else
        local dir="${3}"
    fi

    log_debug "copy_files: Get filename..."
    local filename="${dir}${1##*/}${4}"

    if [[ -e "${filename}" && -z "${4}" ]]; then
        log_info "copy_files: file exists, ID=0"
        copy_files "${1}" "${2}" "${3}" 1
        return 0
    elif [[ -e "${filename}" ]]; then
        local _id="${4}"
        log_info "copy_files: file exists, ID=${4}"
        copy_files "${1}" "${2}" "${3}" $((_id + 1))
        return 0
    fi

    if [[ "${type}" == "file" ]]; then
        if [[ -f "${1}" ]]; then
            log_info "copy_files: copy file ${1}"
            cp -f "${1}" "${filename}"
        else
            log_warning "copy_files: File not found: ${1}"
        fi
    elif [[ "${type}" == "dir"  ]]; then
        if [[ -d "${1}" ]]; then
            log_info "copy_files: copy directory ${1}"
            cp -Rf "${1}" "${filename}"
        else
            log_warning "copy_files: Directory not found: ${1}"
        fi
    else
        show_info "copy_files: error: bad argument 2 ('${2}') should be 'dir' or 'filename'"
        log_error "copy_files: error: bad argument 2 ('${2}') should be 'dir' or 'filename'"
    fi
}

function do_help() {
    #
    # @desc   :: This function prints help message and exit (code 1)
    #

    echo "Description: ${DESCRIPTION}"
    echo "USAGES: ${FILENAME} [-h] [-c] [-d] [-l] [-f]"
    echo $'\t -h/--help: this help message'
    echo $'\t -c/--no-color: disabled colors (useful for output redirection)'
    echo $'\t -d/--no-debug: disabled breakpoints (interactive mode for debugging)'
    echo $'\t -l/--no-logs: no logs'
    echo $'\t -f/--fast: fast mode (no files analysis and reporting)'
    trap - EXIT
    exit 1
}

function you_are_not_root() {
    #
    # @desc   :: This function prints error message and exit (code 3) if you are not root
    #

    log_info "Check permissions..."

    if [ "$(id -u)" -ne 0 ]; then
        log_critical "Permission denied, are you root?"
        show_info "Error: requested operation requires superuser privilege" "ERROR"
        trap - EXIT
        exit 3
    fi
}

function parse_args() {
    #
    # @desc   :: This function parse command line arguments
    # @params :: string[] $@ - Command line arguments
    #

    log_debug "Processing arguments..."

    while [[ $# > 0 ]]
    do
        case "$1" in
            -f|--fast)
                    _ADD=5
                    log_debug "Fast mode is enabled"
                    shift
                    ;;
            -c|--no-color)
                    COLOR=0
                    log_debug "Colors are disabled"
                    shift
                    ;;
            -d|--no-debug)
                    DEBUG=0
                    log_warning "Breakpoints are disabled"
                    shift
                    ;;
            -l|--no-logs)
                    LOG_LEVEL=51  # "${2}"
                    log_warning "Logs are disabled"
                    shift
                    ;;
            -v|--version)
                    echo "${FILENAME} ${VERSION}"
                    trap - EXIT
                    exit 2
                    ;;
            --help|-h|*)
                    do_help
                    ;;
        esac
    done

    log_debug "Arguments are parsed."
}

function on_error() {
    #
    # @desc   :: This function starts on error, launch a breakpoint, change directory and exit (code: 127)
    #

    echo -e "\x1b[K"
    log_debug "In breakpoint for unknow error..."
    BREAKPOINT "unknow error"
    trap - EXIT
    exit 127
}

function on_ctrl_c() {
    #
    # @desc   :: This function starts on error, launch a breakpoint, change directory and exit (code: 127)
    #

    echo -e "\x1b[K"
    log_debug "In breakpoint for <Ctrl + C>, exit code 5"
    BREAKPOINT "<Ctrl + C> Breakpoint"
    trap - EXIT
    exit 4
}

function main() {
    #
    # @desc   :: The main function to call forensic collection functions
    # @params :: string[] $@ - Command line arguments
    #

    trap on_error EXIT
    trap on_ctrl_c INT

    echo "${COPYRIGHT}"
    echo '
 ░░░░░░ ░░      ░░░░░░░ ░░░░░░░ 
▒▒      ▒▒      ▒▒      ▒▒      
▒▒      ▒▒      ▒▒▒▒▒   ▒▒▒▒▒   
▓▓      ▓▓      ▓▓      ▓▓      
 ██████ ███████ ███████ ██      

'

    parse_args $@
    you_are_not_root

    mkdir "${DIRNAME}" && cd "${DIRNAME}"
    log_info "The report directory is created and it is the new current directory"
    show_info "Start collecting evidences..." "INFO" $POURCENT

    get_commands
    POURCENT=$((POURCENT+_ADD))

    if [[ ${_ADD} -eq 1 ]]; then
        log_debug "Calcul file number and pourcent..."
        show_info "Research all files..." "INFO" $POURCENT
        TOTAL_FILE=$(find / \( -not \( -path "/proc/*" -o -path "/sys/*" \) -type f -a ! -type l \) 2>/dev/null | wc -l) # $(ls -1 /** | wc -l)
        ONE_POURCENT=$((TOTAL_FILE / 40 + 1))

        get_files
        get_regex_match
    else
        log_warning "Do not process files and regex, cause of fast mode (option: -f/--fast)"
        show_info "Do not process files and regex, cause of fast mode (option: -f/--fast)" "NOK"
    fi

    get_environment_vars
    POURCENT=$((POURCENT+_ADD))

    get_modules
    POURCENT=$((POURCENT+_ADD))

    get_system
    POURCENT=$((POURCENT+_ADD))

    get_disks
    POURCENT=$((POURCENT+_ADD))

    get_packages
    POURCENT=$((POURCENT+_ADD))

    get_accounts
    POURCENT=$((POURCENT+_ADD))

    get_process
    POURCENT=$((POURCENT+_ADD))

    get_services
    POURCENT=$((POURCENT+_ADD))

    get_opened_ports
    POURCENT=$((POURCENT+_ADD))

    get_arp_cache
    POURCENT=$((POURCENT+_ADD))

    get_network_traffic
    POURCENT=$((POURCENT+_ADD))

    get_network_interfaces
    POURCENT=$((POURCENT+_ADD))

    get_tasks
    POURCENT=$((POURCENT+_ADD))

    get_hardware
    POURCENT=$((POURCENT+_ADD))

    get_logs
    POURCENT=$((POURCENT+_ADD))

    get_configurations
    POURCENT=$((POURCENT+_ADD))

    get_webserverscripts
    POURCENT=$((POURCENT+_ADD))

    get_histories
    POURCENT=$((POURCENT+_ADD))

    get_suspicious
    POURCENT=$((POURCENT+_ADD))

    get_states

    show_info "Evidences are collected successfully !" "OK" $POURCENT
    echo -e "\n"
    trap - EXIT
    exit 0
}

export -f BREAKPOINT
main $@
