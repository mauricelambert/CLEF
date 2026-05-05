#!/usr/bin/env bash

###################
#    CLEF - Collect Linux Evidence for Forensics
#    Copyright (C) 2022, 2026  Maurice Lambert
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

#
# This script collects evidence on a Linux system.
# Compatible: Debian/Ubuntu, RedHat/CentOS/Fedora, Arch, Alpine, and minimal
# systems like Docker containers.
# Supports: offline mode, chroot, isolated environments.
#

set -euo pipefail
IFS=$'\n\t'

readonly SHELL_USED="${_}"
readonly FILENAME="${0##*/}"
readonly VERSION="0.1.0"
readonly AUTHOR="Maurice LAMBERT"
readonly DESCRIPTION="Collects maximum evidence for forensic investigations on Linux."
readonly COPYRIGHT='
CLEF (Collect Linux Evidence for Forensics)  Copyright (C) 2022, 2026  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
'

DEBUG=1
COLOR=1
LOG_LEVEL=10
DATE="$(date +'%Y%m%d_%H%M%S')"
DIRNAME="${FILENAME%.*}_${DATE}"
LAUNCH_PWD="$(pwd)"
LOG_FILE="${LAUNCH_PWD}/${DIRNAME}_LOG.csv"
COMMAND_FILE="file"
TOTAL_FILE=0
ONE_POURCENT=0
_ADD=1
POURCENT=0
FAST_MODE=0
STDOUT="/dev/stdout"
START_TIME="$(date +%s)"

commands=""

declare -A LOG_LEVELS=(
    [10]="DEBUG    (10)"
    [20]="INFO     (20)"
    [30]="WARNING  (30)"
    [40]="ERROR    (40)"
    [50]="CRITICAL (50)"
)

declare -A show_info_actions=(
    [OK]="\x1b[32m[+]"
    [NOK]="\x1b[33m[-]"
    [ERROR]="\x1b[31m[!]"
    [INFO]="\x1b[34m[*]"
    [TODO]="\x1b[35m[#]"
    [ASK]="\x1b[36m[?]"
)

trap on_error EXIT
trap on_ctrl_c INT

function to_CSV() {
    local string=""
    while [[ $# -gt 0 ]]; do
        string+=",\"${1//\"/\"\"}\""
        shift
    done
    echo "${string:1}"
    return 0
}

function logging() {
    local log_message="${1}"
    local level="${2}"
    local localization="${3:-$(caller)}"

    if [[ "${level}" -lt "${LOG_LEVEL}" ]]; then
        return 0
    fi

    local level_str="${LOG_LEVELS[${level}]}"
    to_CSV "$(date +'%Y-%m-%d %T')" "${level_str}" "${FILENAME}" "$$" \
        "${SHELL_USED}" "${localization}" "${log_message}" >> "${LOG_FILE}"
    return 0
}

function log_debug()    { logging "${1}" 10 "$(caller)"; }
function log_info()     { logging "${1}" 20 "$(caller)"; }
function log_warning()  { logging "${1}" 30 "$(caller)"; }
function log_error()    { logging "${1}" 40 "$(caller)"; }
function log_critical() { logging "${1}" 50 "$(caller)"; }

function show_info() {
    local string="${1}"
    local state="${2:-OK}"
    local pourcent="${3:-}"
    local start="\x1b[K${4:-}"
    local end="${5:-\n}"
    local same_line="${6:-0}"

    local state_str="${show_info_actions[${state}]}"

    if [[ -n "${pourcent}" ]]; then
        local progressbar=" |"
        for i in {1..20}; do
            if [[ "${pourcent}" -ge $((i * 5)) ]]; then
                progressbar+="\xe2\x96\x88"
            else
                progressbar+=" "
            fi
        done
        progressbar+="|"

        local pourcent_state color_end
        if [[ "${COLOR}" -eq 0 ]]; then
            pourcent_state="${show_info_actions[INFO]:8}"
            color_end=""
        else
            pourcent_state="${show_info_actions[INFO]}"
            color_end="\x1b[0m"
        fi

        if [[ "${same_line}" -eq 0 ]]; then
            end="${end}${pourcent_state} ${pourcent}%${progressbar}${color_end}\r"
        else
            end=" ${pourcent_state:0:-3} ${pourcent}%${progressbar}${color_end}${end}"
        fi
    fi

    if [[ "${COLOR}" -eq 0 ]]; then
        echo -en "${start}${state_str:8} ${string}${end}\x1b[F" > "${STDOUT}"
    else
        echo -en "${start}${state_str} ${string}\x1b[0m${end}\x1b[F" > "${STDOUT}"
    fi
}

function BREAKPOINT() {
    [[ "${DEBUG}" -eq 0 ]] && return 0

    local BREAKPOINT_NAME="${*}"
    show_info "Enter breakpoint ${BREAKPOINT_NAME}" "INFO" "${POURCENT}"
    set +e
    /bin/bash
    local BREAKPOINT_EXIT_CODE=$?
    set -e

    if [[ "${BREAKPOINT_EXIT_CODE}" -eq 0 ]]; then
        show_info "Continue after breakpoint ${BREAKPOINT_NAME}" "INFO" "${POURCENT}"
        return 0
    else
        show_info "Terminate after breakpoint ${BREAKPOINT_NAME}" "ERROR" "${POURCENT}"
        trap - EXIT
        exit "${BREAKPOINT_EXIT_CODE}"
    fi
}

function run_if_available() {
    # Usage: run_if_available <output_file> <command> [args...]
    local outfile="${1}"
    shift
    local cmd="${1}"

    if has_command "${cmd}"; then
        log_info "Running: ${*}"
        "$@" > "${outfile}" 2>>errors.txt || true
    fi
}

function has_command() {
    echo "${commands}" | grep -qxF "${1}"
}

function copy_files() {
    local src="${1}"
    local type="${2:-file}"
    local destdir="${3:-./}"
    local suffix="${4:-}"

    local base="${src##*/}"
    local dest="${destdir}${base}${suffix}"

    if [[ -e "${dest}" && -z "${suffix}" ]]; then
        copy_files "${src}" "${type}" "${destdir}" "_1"
        return 0
    elif [[ -e "${dest}" ]]; then
        local n="${suffix#_}"
        copy_files "${src}" "${type}" "${destdir}" "_$(( n + 1 ))"
        return 0
    fi

    if [[ "${type}" == "file" ]]; then
        if [[ -f "${src}" ]]; then
            log_info "copy_files: copy file ${src} -> ${dest}"
            cp -f "${src}" "${dest}" 2>/dev/null || log_warning "copy_files: cannot copy ${src}"
        else
            log_warning "copy_files: File not found: ${src}"
        fi
    elif [[ "${type}" == "dir" ]]; then
        if [[ -d "${src}" ]]; then
            log_info "copy_files: copy directory ${src} -> ${dest}"
            cp -Rf "${src}" "${dest}" 2>/dev/null || log_warning "copy_files: cannot copy dir ${src}"
        else
            log_warning "copy_files: Directory not found: ${src}"
        fi
    else
        log_error "copy_files: bad type argument '${type}' (should be 'file' or 'dir')"
    fi
}

function gz_text_file() {
    local f="${1}"
    [[ -f "${f}" ]] || return 0
    [[ "${f}" == *.gz || "${f}" == *.bz2 || "${f}" == *.xz || "${f}" == *.zst ]] && return 0
    [[ -s "${f}" ]] || return 0
    gzip -f "${f}" 2>/dev/null || true
}

function gz_dir_text_files() {
    local dir="${1}"
    find "${dir}" -type f \( \
        -name "*.txt" -o -name "*.csv" -o -name "*.log" \
        -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \
        -o -name "*.html" -o -name "*.json" -o -name "*.xml" \
        -o -name "*.sh"  -o -name "*.py"  -o -name "*.rb" \
        -o -name "*.php" -o -name "*.js"  -o -name "*.pl" \
        -o -name "*.go"  -o -name "*.cgi" \
    \) ! -name "*.gz" | while IFS= read -r f; do
        gz_text_file "${f}"
    done
}

function get_commands() {
    show_info "Processing commands and aliases..." "INFO" "${POURCENT}"
    local dir="commands"
    mkdir "${dir}" && cd "${dir}"

    set +e
    commands=$(echo -n "$PATH" | xargs -d : -I {} find {} -maxdepth 1 -executable \( -type f -o -type l \) -printf '%P\n' 2>errors.txt | sort -u)
    set -e

    local aliases_name
    aliases_name=$(alias | cut -d '=' -f 1 | sed 's/^alias //')

    {
        echo "${commands}"
        echo "${aliases_name}"
    } | sort -u > commands_and_aliases.txt

    echo "${commands}" > commands.txt
    echo "${aliases_name}" > aliases_name.txt
    alias > aliases.txt 2>/dev/null || true

    if ! echo "${commands}" | grep -qxF "file"; then
        log_warning "'file' command not found. File type detection disabled."
        show_info "'file' command not found – file type detection disabled." "NOK"
        COMMAND_FILE=/bin/true
    fi

    log_info "Commands and aliases saved."
    cd ..
    show_info "COLLECTED: commands and aliases" "OK" "${POURCENT}"
}

function get_files() {
    show_info "Processing files..." "INFO" "${POURCENT}"
    local dir="files"
    mkdir "${dir}" && cd "${dir}"

    if has_command "lsof"; then
        lsof +L > "lsof_L.txt" 2>>errors.txt || true
    fi

    to_CSV path filename permissions user group size type birthdate accessdate modificationdate statusdate hash filetype > "files.csv"

    shopt -s globstar
    local counter=1
    local counter_total=1

    for filename in /**; do
        if [[ -f "${filename}" && ! -h "${filename}" \
            && "${filename:0:6}" != "/proc/" \
            && "${filename:0:5}" != "/sys/" ]]; then

            local _hash
            _hash=$(md5sum "${filename}" 2>/dev/null | grep -oE "^[0-9a-f]+") || _hash="error"

            to_CSV "${filename}" \
                "$(stat -c '%N %A %U %G %s %F %w %x %y %z' "${filename}" 2>/dev/null || true)" \
                "${_hash}" \
                "$("${COMMAND_FILE}" "${filename}" 2>/dev/null || true)" \
                >> "files.csv"

            (( counter++ )) || true
            (( counter_total++ )) || true

            if [[ "${ONE_POURCENT}" -gt 0 && "${counter}" -ge "${ONE_POURCENT}" ]]; then
                counter=1
                (( POURCENT++ )) || true
                show_info "${counter_total} / ${TOTAL_FILE} files processed" "OK" "${POURCENT}" "" "\r" "1"
            fi

        elif [[ -e "${filename}" ]]; then
            to_CSV "${filename}" \
                "$(stat -c '%N %A %U %G %s %F %w %x %y %z' "${filename}" 2>/dev/null || true)" \
                "" \
                "$("${COMMAND_FILE}" "${filename}" 2>/dev/null || true)" \
                >> "files.csv"
        fi
    done

    shopt -u globstar
    cd ..
    show_info "COLLECTED: files" "OK" "${POURCENT}"
}

function get_regex_match() {
    show_info "Processing regex matches in files..." "INFO" "${POURCENT}"
    local dir="regex"
    mkdir "${dir}" && cd "${dir}"

    shopt -s globstar
    local counter=1
    local counter_total=1

    for filename in /**; do
        if [[ -f "${filename}" && ! -h "${filename}" \
            && "${filename:0:6}" != "/proc/" \
            && "${filename:0:5}" != "/sys/" ]]; then

            local data
            data=$(strings "${filename}" 2>/dev/null) || continue

            echo "${data}" | grep -oE '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' \
                >> ipv4.txt 2>/dev/null || true
            echo "${data}" | grep -oP '(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}' \
                >> domain.txt 2>/dev/null || true
            echo "${data}" | grep -oP '((http|https)://)(www\.)?[a-zA-Z0-9@:%._\+~#?&//=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%._\+~#?&//=]*)' \
                >> urls.txt 2>/dev/null || true
            echo "${data}" | grep -oP '(?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)' \
                >> base64.txt 2>/dev/null || true
            echo "${data}" | grep -oP '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' \
                >> email.txt 2>/dev/null || true
            echo "${data}" | grep -oiP '\{?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}?' \
                >> uuid.txt 2>/dev/null || true
            echo "${data}" | grep -oP '(%(25)?[0-9A-Fa-f]{2}){5,}' \
                >> urlencode.txt 2>/dev/null || true
            echo "${data}" | grep -oP 'AKIA[0-9A-Z]{16}' \
                >> aws_access_keys.txt 2>/dev/null || true
            grep -l "BEGIN.*PRIVATE KEY" "${filename}" \
                >> private_key_files.txt 2>/dev/null || true

            (( counter++ )) || true
            (( counter_total++ )) || true

            if [[ "${ONE_POURCENT}" -gt 0 && "${counter}" -ge "${ONE_POURCENT}" ]]; then
                counter=1
                (( POURCENT++ )) || true
                show_info "${counter_total} / ${TOTAL_FILE} files processed (regex)" "OK" "${POURCENT}" "" "\r" "1"
            fi
        fi
    done

    for f in ipv4.txt domain.txt urls.txt email.txt uuid.txt aws_access_keys.txt; do
        [[ -f "${f}" ]] && sort -u "${f}" -o "${f}"
    done

    shopt -u globstar
    cd ..
    show_info "COLLECTED: regex matches" "OK" "${POURCENT}"
}

function get_environment_vars() {
    show_info "Processing environment variables..." "INFO" "${POURCENT}"
    local dir="environment_vars"
    mkdir "${dir}" && cd "${dir}"

    printenv  > printenv.txt  2>>errors.txt || true
    export    > export.txt    2>>errors.txt || true
    env       > env.txt       2>>errors.txt || true
    declare -f > declare_functions.txt 2>>errors.txt || true
    (set -o posix; set) > set.txt 2>>errors.txt || true

    cd ..
    show_info "COLLECTED: environment variables" "OK" "${POURCENT}"
}

function get_modules() {
    show_info "Processing kernel modules..." "INFO" "${POURCENT}"
    local dir="modules"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "lsmod.txt"   lsmod
    cat /proc/modules > "proc_modules.txt" 2>>errors.txt || true

    if has_command "lsmod" && has_command "modprobe"; then
        lsmod | awk '$2 ~ /[0-9]+/ { print $1 }' | while IFS= read -r module; do
            modprobe --show-depends "${module}" >> "modprobe_depends.txt" 2>>errors.txt || true
        done
    fi

    if has_command "lsmod" && has_command "modinfo"; then
        lsmod | awk '$2 ~ /[0-9]+/ { print $1 }' | while IFS= read -r module; do
            modinfo "${module}" >> "modinfo.txt" 2>>errors.txt || true
        done
    fi

    if [[ -f /proc/sys/kernel/tainted ]]; then
        cat /proc/sys/kernel/tainted > "kernel_tainted.txt" 2>>errors.txt || true
    fi

    cd ..
    show_info "COLLECTED: kernel modules" "OK" "${POURCENT}"
}

function get_system() {
    show_info "Processing system info..." "INFO" "${POURCENT}"
    local dir="system"
    mkdir "${dir}" && cd "${dir}"

    cat /proc/version          > "proc_version.txt"   2>>errors.txt || true
    run_if_available "uname.txt" uname -a
    run_if_available "hostname.txt" hostname
    run_if_available "ip.txt"    hostname -I

    for f in /etc/os-release /etc/lsb-release /etc/redhat-release \
              /etc/debian_version /etc/alpine-release; do
        [[ -f "${f}" ]] && { cat "${f}" > "${f##*/}.txt" 2>>errors.txt || true; }
    done

    timedatectl > "timedatectl.txt" 2>>errors.txt || \
        { cat /etc/timezone > "timezone.txt" 2>/dev/null || true; }

    run_if_available "uptime.txt" uptime

    if has_command "systemd-analyze"; then
        systemd-analyze                > "systemd_analyze.txt"        2>>errors.txt || true
        systemd-analyze blame          > "systemd_analyze_blame.txt"  2>>errors.txt || true
        systemd-analyze critical-chain > "systemd_critical_chain.txt" 2>>errors.txt || true
    fi

    run_if_available "locale.txt" locale

    cd ..
    show_info "COLLECTED: system info" "OK" "${POURCENT}"
}

function get_disks() {
    show_info "Processing disks..." "INFO" "${POURCENT}"
    local dir="disks"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "fdisk.txt"     fdisk -l
    run_if_available "df.txt"        df -h
    run_if_available "findmnt.txt"   findmnt -a -A
    run_if_available "lsblk.txt"     lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,MODEL
    run_if_available "blkid.txt"     blkid
    run_if_available "free.txt"      free -h
    run_if_available "vgdisplay.txt" vgdisplay -v
    run_if_available "lvdisplay.txt" lvdisplay -v
    run_if_available "vgs.txt"       vgs --all
    run_if_available "lvs.txt"       lvs --all

    cat /proc/partitions > "proc_partitions.txt" 2>>errors.txt || true
    cat /proc/mounts     > "proc_mounts.txt"     2>>errors.txt || true
    cat /proc/swaps      > "proc_swaps.txt"      2>>errors.txt || true

    [[ -e "/dev/mapper" ]] && ls -l /dev/mapper > "mapper.txt" 2>>errors.txt || true

    set +e
    du -sh / > "du_root.txt" 2>>errors.txt || true
    set -e

    copy_files "/etc/fstab"
    copy_files "/etc/mtab"

    cd ..
    show_info "COLLECTED: disks" "OK" "${POURCENT}"
}

function get_packages() {
    show_info "Processing installed packages..." "INFO" "${POURCENT}"
    local dir="packages"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "pacman.txt"      pacman -Q
    run_if_available "apk.txt"         apk info -vv
    run_if_available "apt.txt"         apt list --installed
    run_if_available "dpkg.txt"        dpkg -l
    run_if_available "dpkg-query.txt"  dpkg-query -l
    run_if_available "yum.txt"         yum list installed
    run_if_available "dnf.txt"         dnf list installed
    run_if_available "zypper.txt"      zypper se --installed-only
    run_if_available "rpm.txt"         rpm -qa
    run_if_available "snap.txt"        snap list
    run_if_available "flatpak.txt"     flatpak list --app
    run_if_available "dpkg_verify.txt" dpkg -V
    if has_command "rpm"; then
        set +e
        rpm -Va > "rpm_verify.txt" 2>>errors.txt || true
        set -e
    fi

    cd ..
    show_info "COLLECTED: packages" "OK" "${POURCENT}"
}

function get_accounts() {
    show_info "Processing accounts..." "INFO" "${POURCENT}"
    local dir="accounts"
    mkdir "${dir}" && cd "${dir}"

    for f in /etc/passwd /etc/passwd- /etc/group /etc/group- \
              /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do
        copy_files "${f}"
    done

    who -alpu > "who.txt" 2>>errors.txt || true
    run_if_available "last.txt"    last -Faixw
    run_if_available "lastlog.txt" lastlog
    run_if_available "w.txt"       w
    run_if_available "id.txt"      id

    awk -F: '$2=="" || $2="!" { print $0 }' /etc/shadow > "shadow_empty_or_locked.txt" 2>/dev/null || true
    awk -F: '$3==0 { print $0 }' /etc/passwd > "uid0_accounts.txt" 2>/dev/null || true
    grep -vE '(nologin|false)$' /etc/passwd > "passwd_shell_users.txt" 2>/dev/null || true

    mkdir "ssh_authorized_keys"
    while IFS=: read -r username _ _ _ _ homedir _; do
        local keyfile="${homedir}/.ssh/authorized_keys"
        if [[ -f "${keyfile}" ]]; then
            copy_files "${keyfile}" "file" "ssh_authorized_keys/" "_${username}"
        fi
    done < /etc/passwd

    cd ..
    show_info "COLLECTED: accounts" "OK" "${POURCENT}"
}

function get_process() {
    show_info "Processing processes..." "INFO" "${POURCENT}"
    local dir="process"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "pstree.txt"  pstree -alpn
    run_if_available "ps_faux.txt" ps faux
    run_if_available "ps_ef.txt"   ps -ef
    run_if_available "top.txt"     top -H -b -n 1

    if has_command "ps"; then
        ps -ewo "pid,ppid,etime,time,user,comm,args" > "ps_full.txt" 2>>errors.txt || true
    fi

    if has_command "cat"; then
        mkdir "proc_maps"
        for pid_dir in /proc/[0-9]*/; do
            local pid="${pid_dir%/}"
            pid="${pid##*/}"
            if [[ -f "${pid_dir}maps" ]]; then
                cat "${pid_dir}maps" > "proc_maps/${pid}_maps.txt" 2>/dev/null || true
            fi
        done
    fi

    if has_command "lsof"; then
        lsof -n -P > "lsof_all.txt" 2>>errors.txt || true
    fi

    find /proc -maxdepth 3 -name exe -type l 2>/dev/null | while IFS= read -r exelink; do
        if ls -la "${exelink}" 2>/dev/null | grep -q "(deleted)"; then
            echo "${exelink}" >> "deleted_executables.txt"
        fi
    done || true

    cd ..
    show_info "COLLECTED: processes" "OK" "${POURCENT}"
}

function get_services() {
    show_info "Processing services..." "INFO" "${POURCENT}"
    local dir="services"
    mkdir "${dir}" && cd "${dir}"

    shopt -s globstar
    run_if_available "systemctl_all.txt"     systemctl list-units --all
    run_if_available "service_status_all.txt" service --status-all
    run_if_available "firewall_cmd_list_services.txt" firewall-cmd --list-services
    run_if_available "sysv_rc_conf_list.txt" sysv-rc-conf --list
    run_if_available "chkconfig_list.txt" chkconfig --list

    if has_command "systemctl"; then
        systemctl --type=service --state=failed  > "systemctl_failed.txt"  2>>errors.txt || true
        systemctl --type=service --state=active  > "systemctl_active.txt"  2>>errors.txt || true
        systemctl --type=service --state=running > "systemctl_running.txt" 2>>errors.txt || true
        systemctl list-timers --all              > "systemctl_timers.txt"  2>>errors.txt || true
        systemctl list-unit-files                > "systemctl_unit_files.txt" 2>>errors.txt || true
    fi

    ls -la /etc/init.d/ > "ls_initd.txt" 2>>errors.txt || true
    ls -la /etc/systemd/system/ > "ls_systemd_system.txt" 2>>errors.txt || true
    ls -la /usr/lib/systemd/ > "ls_usr_lib_system.txt" 2>>errors.txt || true
    shopt -u globstar

    cd ..
    show_info "COLLECTED: services" "OK" "${POURCENT}"
}

function get_opened_ports() {
    show_info "Processing open ports and connections..." "INFO" "${POURCENT}"
    local dir="ports"
    mkdir "${dir}" && cd "${dir}"

    if has_command "ss"; then
        ss -tnp state established > "ss_established.txt" 2>>errors.txt || true
        ss --all --numeric --processes > "ss_all.txt" 2>>errors.txt || true
        ss -lntuap > "ss_listen.txt" 2>>errors.txt || true
    fi

    if has_command "netstat"; then
        netstat -a > "netstat_all.txt" 2>>errors.txt || true
        netstat -lntu > "netstat_listen.txt" 2>>errors.txt || true
    fi

    if has_command "firewall-cmd"; then
        firewall-cmd --list-all    > "firewall_cmd_all.txt"   2>>errors.txt || true
        firewall-cmd --list-ports  > "firewall_cmd_ports.txt" 2>>errors.txt || true
    fi

    if has_command "iptables"; then
        iptables -L -v -n  > "iptables_filter.txt" 2>>errors.txt || true
        iptables -t nat -L -v -n > "iptables_nat.txt" 2>>errors.txt || true
    fi

    if has_command "ip6tables"; then
        ip6tables -L -v -n > "ip6tables_filter.txt" 2>>errors.txt || true
    fi

    if has_command "nft"; then
        nft list ruleset > "nft_ruleset.txt" 2>>errors.txt || true
    fi

    if has_command "lsof"; then
        lsof -i -n -P > "lsof_ports.txt" 2>>errors.txt || true
        lsof -i -n -P | awk ' $0 ~ "LISTEN" { print $0 } ' > "lsof_listening_ports.txt" 2>>errors.txt || true
    fi

    cd ..
    show_info "COLLECTED: open ports & connections" "OK" "${POURCENT}"
}

function get_arp_cache() {
    show_info "Processing ARP cache..." "INFO" "${POURCENT}"
    local dir="arp"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "arp.txt" arp -a
    cat /proc/net/arp > "proc_net_arp.txt" 2>>errors.txt || true

    if has_command "ip"; then
        ip neigh show > "ip_neigh.txt" 2>>errors.txt || true
    fi

    cd ..
    show_info "COLLECTED: ARP cache" "OK" "${POURCENT}"
}

function get_network_traffic() {
    show_info "Processing network traffic statistics..." "INFO" "${POURCENT}"
    local dir="traffic"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "ip_stats.txt" ip -s -s link
    grep -H . /sys/class/net/*/statistics/rx_packets > "rx_packets.txt" 2>>errors.txt || true
    grep -H . /sys/class/net/*/statistics/tx_packets > "tx_packets.txt" 2>>errors.txt || true
    grep -H . /sys/class/net/*/statistics/rx_errors  > "rx_errors.txt"  2>>errors.txt || true
    grep -H . /sys/class/net/*/statistics/tx_errors  > "tx_errors.txt"  2>>errors.txt || true

    if has_command "ip" && has_command "ethtool"; then
        local _interfaces
        _interfaces=$(ip addr show | awk '$0 ~ /^[0-9]+:\s+\w+:/ { print $2 }' | tr -d ':') || true
        for _iface in ${_interfaces}; do
            [[ "${_iface}" == "lo" ]] && continue
            ethtool -S "${_iface}" > "ethtool_${_iface}.txt" 2>>errors.txt || true
        done
    fi

    cd ..
    show_info "COLLECTED: network traffic statistics" "OK" "${POURCENT}"
}

function get_network_interfaces() {
    show_info "Processing network interfaces..." "INFO" "${POURCENT}"
    local dir="interfaces"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "ifconfig.txt"       ifconfig -a
    run_if_available "iwconfig.txt"       iwconfig
    run_if_available "ip_addr.txt"        ip addr
    run_if_available "ip_route.txt"       ip route
    run_if_available "ip_rule.txt"        ip rule
    run_if_available "netstat_i.txt"      netstat -i
    run_if_available "nmcli.txt"          nmcli device status
    run_if_available "lshw_network.txt"   lshw -class network -short
    run_if_available "hwinfo_network.txt" hwinfo --short --network
    run_if_available "inxi_network.txt"   inxi -N

    if has_command "lspci"; then
        lspci | awk ' tolower($0) ~ /network|ethernet|wireless|wi-fi/ { print $0 } ' > "lspci_if.txt" 2>>errors.txt || true
    fi

    cat /proc/net/dev > "proc_net_dev.txt" 2>>errors.txt || true

    for f in /etc/hosts /etc/hosts.allow /etc/hosts.deny \
              /etc/resolv.conf /etc/nsswitch.conf /etc/network/interfaces; do
        [[ -f "${f}" ]] && copy_files "${f}"
    done

    run_if_available "resolvectl.txt" resolvectl status

    cd ..
    show_info "COLLECTED: network interfaces" "OK" "${POURCENT}"
}

function get_tasks() {
    show_info "Processing scheduled tasks..." "INFO" "${POURCENT}"
    local dir="tasks"
    mkdir "${dir}" && cd "${dir}"

    shopt -s globstar

    declare -A task_files=(
        [bashrc]="/etc/*bashrc* /home/*/.bashrc* /home/*/.bash_profile* /home/*/.profile* /home/*/.bash_login /root/.bashrc* /root/.profile* /root/.bash_login"
        [cron]="/etc/*cron*/* /etc/cron* /var/spool/**/cron*"
        [service]="/etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service"
        [rc]="/etc/rc*.d/* /etc/rc.local*"
        [atjobs]="/var/spool/at/* /var/spool/atjobs/*"
    )

    for category in "${!task_files[@]}"; do
        mkdir -p "${category}"
        for pattern in ${task_files[$category]}; do
            for f in ${pattern}; do
                [[ -e "${f}" ]] && copy_files "${f}" "file" "${category}/"
            done
        done
    done

    shopt -u globstar

    set +e
    while IFS=: read -r username _ _ _ _ _ _; do
        crontab -u "${username}" -l > "crontab_${username}.txt" 2>>errors.txt || true
    done < /etc/passwd
    set -e

    run_if_available "atq.txt" atq

    cd ..
    show_info "COLLECTED: scheduled tasks" "OK" "${POURCENT}"
}

function get_hardware() {
    show_info "Processing hardware..." "INFO" "${POURCENT}"
    local dir="hardware"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "lspci.txt"     lspci -kDq
    run_if_available "lsusb.txt"     lsusb
    run_if_available "dmidecode.txt" dmidecode
    run_if_available "lscpu.txt"     lscpu
    run_if_available "lsmem.txt"     lsmem

    cat /proc/cpuinfo > "cpuinfo.txt" 2>>errors.txt || true
    cat /proc/meminfo > "meminfo.txt" 2>>errors.txt || true

    [[ -d /sys/firmware/efi ]] && echo "UEFI" > "firmware_type.txt" || echo "BIOS/Legacy" > "firmware_type.txt"

    cd ..
    show_info "COLLECTED: hardware" "OK" "${POURCENT}"
}

function get_logs() {
    show_info "Processing logs..." "INFO" "${POURCENT}"
    local dir="logs"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "last.txt" last -Faixw

    if has_command "journalctl"; then
        journalctl -x --no-pager > "journalctl_x.txt" 2>>errors.txt || true
        journalctl -k --no-pager > "journalctl_k.txt" 2>>errors.txt || true
    fi

    if has_command "dmesg"; then
        set +e
        dmesg -T > "dmesg.txt" 2>>errors.txt || true
        set -e
    fi

    run_if_available "ausearch.txt"  ausearch -ts recent
    run_if_available "aureport.txt"  aureport
    [[ -d /var/log/audit ]] && ls /var/log/audit/ > "audit_dir_listing.txt" 2>>errors.txt || true

    shopt -s globstar
    declare -A log_paths=(
        [apache_access]="/var/log/apache*/**access*"
        [apache_error]="/var/log/apache*/**error*"
        [auth]="/var/log/auth**"
        [boot]="/var/log/boot**"
        [btmp]="/var/log/btmp**"
        [wtmp]="/var/log/wtmp**"
        [httpd_access]="/var/log/httpd/**access*"
        [httpd_error]="/var/log/httpd/**error*"
        [kern]="/var/log/kern**"
        [mail]="/var/log/mail**"
        [mariadb]="/var/log/mariadb/**"
        [messages]="/var/log/message**"
        [mysql]="/var/log/mysql/**"
        [nginx_access]="/var/log/nginx/**access*"
        [nginx_error]="/var/log/nginx/**error*"
        [secure]="/var/log/secure**"
        [syslog]="/var/log/syslog**"
        [audit]="/var/log/audit/**"
        [squid_access]="/var/log/squid/**access*"
    )

    for category in "${!log_paths[@]}"; do
        mkdir -p "${category}"
        for pattern in ${log_paths[$category]}; do
            for f in ${pattern}; do
                [[ -f "${f}" ]] && copy_files "${f}" "file" "${category}/"
            done
        done
    done
    shopt -u globstar

    cd ..
    show_info "COLLECTED: logs" "OK" "${POURCENT}"
}

function get_configurations() {
    show_info "Processing configurations..." "INFO" "${POURCENT}"
    local dir="configurations"
    mkdir "${dir}" && cd "${dir}"

    mkdir -p /run/sshd 2>/dev/null || true

    run_if_available "iptables.txt"     iptables -S
    run_if_available "nft_tables.txt"   nft list tables
    run_if_available "firewall_cmd.txt" firewall-cmd --list-all
    run_if_available "sshd_config.txt"  sshd -T
    run_if_available "sysctl.txt"       sysctl -a

    shopt -s globstar
    declare -A conf_paths=(
        [apache]="/etc/apache*/*.conf"
        [apt]="/etc/apt/**/*.list*"
        [apparmor]="/etc/apparmor*/*.conf"
        [avahi]="/etc/avahi/*.conf"
        [firewalld]="/etc/firewalld/*.conf"
        [grub]="/boot/grub/grub.conf* /etc/default/grub"
        [httpd]="/etc/httpd/*.conf"
        [ipsec]="/etc/ipsec* /etc/ipsec/**/*"
        [lighthttpd]="/etc/lighthttpd/*.conf"
        [mariadb]="/etc/mariadb/*"
        [modprobe]="/etc/modprobe.d/* /etc/modprobe.d/**/*"
        [mysql]="/etc/mysql/*"
        [nftables]="/etc/nftables*"
        [nginx]="/etc/nginx/*"
        [ntp]="/etc/ntp*"
        [pam]="/etc/pam* /etc/pam/**/*"
        [postgresql]="/etc/postgresql*/* /etc/postgresql/**/*"
        [resolv]="/etc/resolv*"
        [rsyslog]="/etc/rsyslog* /etc/rsyslog/**/*"
        [samba]="/etc/samba/**/*"
        [security]="/etc/security/**/*"
        [selinux]="/etc/selinux/*"
        [snmp]="/etc/snmp/*"
        [ssh]="/etc/ssh/**/*"
        [sudo]="/etc/sudo* /etc/sudo/**/*"
        [sudoers]="/etc/sudoers* /etc/sudoers/**/*"
        [sysctl]="/etc/sysctl* /etc/sysctl/**/*"
        [yum]="/etc/yum.* /etc/yum/**/*"
        [dnf]="/etc/dnf/**/*"
        [clamav]="/etc/clamav/*"
    )

    for category in "${!conf_paths[@]}"; do
        mkdir -p "${category}"
        for pattern in ${conf_paths[$category]}; do
            for f in ${pattern}; do
                [[ -f "${f}" ]] && copy_files "${f}" "file" "${category}/"
            done
        done
    done
    shopt -u globstar

    cd ..
    show_info "COLLECTED: configurations" "OK" "${POURCENT}"
}

function get_security() {
    show_info "Processing security indicators..." "INFO" "${POURCENT}"
    local dir="security"
    mkdir "${dir}" && cd "${dir}"

    find / -xdev -perm /4000 -type f 2>/dev/null > "suid_files.txt" || true
    find / -xdev -perm /2000 -type f 2>/dev/null > "sgid_files.txt" || true
    find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune \
        -o -perm /o+w -type f -print 2>/dev/null > "world_writable_files.txt" || true
    find / -xdev -nouser -o -nogroup 2>/dev/null > "orphan_files.txt" || true
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null > "tmp_executables.txt" || true
    find /tmp /var/tmp -name ".*" 2>/dev/null > "tmp_hidden_files.txt" || true
    if has_command "ssh-keygen"; then
        for keyfile in /etc/ssh/ssh_host_*_key.pub; do
            [[ -f "${keyfile}" ]] && ssh-keygen -lf "${keyfile}" >> "ssh_host_key_fingerprints.txt" 2>/dev/null || true
        done
    fi

    run_if_available "getenforce.txt"   getenforce
    run_if_available "sestatus.txt"     sestatus
    run_if_available "aa_status.txt"    aa-status
    run_if_available "apparmor_status.txt" apparmor_status
    run_if_available "auditctl_rules.txt" auditctl -l
    copy_files "/etc/audit/audit.rules"
    copy_files "/etc/audit/rules.d"

    if has_command "getcap"; then
        getcap -r / 2>/dev/null > "file_capabilities.txt" || true
    fi

    copy_files "/etc/sudoers"

    cd ..
    show_info "COLLECTED: security indicators" "OK" "${POURCENT}"
}

function get_containers() {
    show_info "Processing container environment..." "INFO" "${POURCENT}"
    local dir="containers"
    mkdir "${dir}" && cd "${dir}"

    local container_type="bare-metal or VM"
    if [[ -f /.dockerenv ]]; then
        container_type="Docker container"
    elif [[ -f /run/.containerenv ]]; then
        container_type="Podman container"
        cat /run/.containerenv > "podman_containerenv.txt" 2>/dev/null || true
    elif grep -qE "(lxc|lxd)" /proc/1/cgroup 2>/dev/null; then
        container_type="LXC/LXD container"
    elif systemd-detect-virt --container 2>/dev/null | grep -qv "none"; then
        container_type="$(systemd-detect-virt --container 2>/dev/null)"
    fi
    echo "${container_type}" > "container_type.txt"

    cat /proc/1/cgroup > "proc_1_cgroup.txt" 2>>errors.txt || true
    ls /sys/fs/cgroup/ > "cgroups_top.txt"   2>>errors.txt || true

    if has_command "lsns"; then
        lsns > "lsns.txt" 2>>errors.txt || true
    fi
    ls -la /proc/1/ns/ > "proc_1_ns.txt" 2>>errors.txt || true

    if has_command "capsh"; then
        capsh --print > "capsh.txt" 2>>errors.txt || true
    fi
    cat /proc/1/status | grep -i cap > "proc_1_capabilities.txt" 2>>errors.txt || true

    run_if_available "docker_info.txt"       docker info
    run_if_available "docker_ps_all.txt"     docker ps -a
    run_if_available "docker_images.txt"     docker images
    run_if_available "docker_networks.txt"   docker network ls
    run_if_available "docker_volumes.txt"    docker volume ls
    run_if_available "podman_ps.txt"         podman ps -a
    run_if_available "podman_images.txt"     podman images
    run_if_available "machinectl.txt"        machinectl list

    cat /proc/1/status | grep -i seccomp > "proc_1_seccomp.txt" 2>>errors.txt || true

    cd ..
    show_info "COLLECTED: container environment" "OK" "${POURCENT}"
}

function get_webserverscripts() {
    show_info "Processing web server scripts..." "INFO" "${POURCENT}"
    local dir="WebServerScripts"
    mkdir "${dir}" && cd "${dir}"

    shopt -s globstar
    for ext in py php js rb pl cgi sh go war jsp aspx; do
        for f in /var/www/**/*.${ext}; do
            [[ -f "${f}" ]] && copy_files "${f}"
        done
    done
    shopt -u globstar

    cd ..
    show_info "COLLECTED: web server scripts" "OK" "${POURCENT}"
}

function get_histories() {
    show_info "Processing shell histories..." "INFO" "${POURCENT}"
    local dir="histories"
    mkdir "${dir}" && cd "${dir}"

    while IFS=: read -r username _ _ _ _ homedir _; do
        for histfile in \
            "${homedir}/.bash_history" \
            "${homedir}/.zsh_history" \
            "${homedir}/.sh_history" \
            "${homedir}/.history" \
            "${homedir}/.python_history" \
            "${homedir}/.mysql_history" \
            "${homedir}/.psql_history" \
            "${homedir}/.lesshst" \
            "${homedir}/.viminfo" \
            "${homedir}/.wget-hsts" \
            "${homedir}/.ssh/known_hosts"; do
            if [[ -f "${histfile}" ]]; then
                local safe_name
                safe_name="${username}_${histfile##*/}"
                cp -f "${histfile}" "${safe_name}" 2>/dev/null || true
            fi
        done
    done < /etc/passwd

    if has_command "history"; then
        history > "current_session_history.txt" 2>>errors.txt || true
    fi

    cd ..
    show_info "COLLECTED: shell histories" "OK" "${POURCENT}"
}

function get_suspicious() {
    show_info "Processing suspicious files..." "INFO" "${POURCENT}"
    local dir="suspicious"
    mkdir "${dir}" && cd "${dir}"

    for tmpdir in /tmp /var/tmp /dev/shm; do
        find "${tmpdir}" -type f -perm /+x 2>/dev/null | while IFS= read -r f; do
            copy_files "${f}"
            echo "${f}: executable in ${tmpdir}" >> report.txt
        done || true
    done

    for tmpdir in /tmp /var/tmp /dev/shm; do
        for f in "${tmpdir}"/**; do
            if [[ -f "${f}" ]] && "${COMMAND_FILE}" "${f}" 2>/dev/null | grep -qE "(ELF|executable|PE32|shared object|script)"; then
                copy_files "${f}"
                echo "${f}: executable type in ${tmpdir}" >> report.txt
            fi
        done 2>/dev/null || true
    done

    find /proc -maxdepth 3 -name exe -type l 2>/dev/null | while IFS= read -r lnk; do
        ls -la "${lnk}" 2>/dev/null | grep -q "(deleted)" && echo "${lnk}" >> "running_deleted_exe.txt"
    done || true

    if has_command "ss"; then
        ss -lntp 2>/dev/null > "ss_listen_detail.txt" || true
    fi

    find /bin /sbin /usr/bin /usr/sbin -newer /etc/passwd -type f 2>/dev/null > "recently_modified_binaries.txt" || true
    find /dev -type f 2>/dev/null > "dev_regular_files.txt" || true

    cd ..
    show_info "COLLECTED: suspicious indicators" "OK" "${POURCENT}"
}

function get_states() {
    show_info "Processing system states..." "INFO" "${POURCENT}"
    local dir="states"
    mkdir "${dir}" && cd "${dir}"

    run_if_available "iostat.txt"   iostat -t -N -x 1 2
    run_if_available "vmstat.txt"   vmstat
    run_if_available "numastat.txt" numastat
    run_if_available "mpstat.txt"   mpstat

    if has_command "nfsstat"; then
        set +e
        nfsstat > "nfsstat.txt" 2>>errors.txt || true
        set -e
    fi

    local proc_files=(
        /proc/interrupts
        /proc/meminfo
        /proc/buddyinfo
        /proc/slabinfo
        /proc/net/netstat
        /proc/net/snmp
        /proc/net/tcp
        /proc/net/tcp6
        /proc/net/udp
        /proc/net/udp6
        /proc/loadavg
        /proc/sys/kernel/hostname
        /proc/sys/kernel/osrelease
        /proc/sys/kernel/dmesg_restrict
        /proc/sys/fs/file-nr
    )

    for pfile in "${proc_files[@]}"; do
        if [[ -f "${pfile}" ]]; then
            cat "${pfile}" > "${pfile##*/}.txt" 2>>errors.txt || true
        fi
    done

    cd ..
    show_info "COLLECTED: system states" "OK" "${POURCENT}"
}

function generate_html_report() {
    show_info "Generating HTML summary report..." "INFO" "${POURCENT}"

    local end_time
    end_time="$(date +%s)"
    local duration=$(( end_time - START_TIME ))
    local hostname_val
    hostname_val="$(hostname 2>/dev/null || echo unknown)"
    local kernel_val
    kernel_val="$(uname -r 2>/dev/null || echo unknown)"
    local os_val
    os_val="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo unknown)"

    cat > "report.html" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CLEF Forensic Report - ${hostname_val} - ${DATE}</title>
<style>
  body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }
  h1 { color: #00d4aa; border-bottom: 2px solid #00d4aa; }
  h2 { color: #4fc3f7; margin-top: 30px; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  th { background: #263238; color: #00d4aa; padding: 8px 12px; text-align: left; }
  td { padding: 6px 12px; border-bottom: 1px solid #333; }
  tr:hover { background: #1e3a4a; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
  .ok   { background: #1b5e20; color: #a5d6a7; }
  .warn { background: #e65100; color: #ffe0b2; }
  .info { background: #0d47a1; color: #bbdefb; }
  pre { background: #263238; padding: 10px; overflow-x: auto; border-left: 3px solid #00d4aa; }
  .section { background: #16213e; border-radius: 6px; padding: 15px; margin: 15px 0; }
</style>
</head>
<body>
<h1>🔍 CLEF Forensic Evidence Report</h1>
<div class="section">
  <h2>Collection Metadata</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Hostname</td><td>${hostname_val}</td></tr>
    <tr><td>OS</td><td>${os_val}</td></tr>
    <tr><td>Kernel</td><td>${kernel_val}</td></tr>
    <tr><td>Collection Date</td><td>$(date)</td></tr>
    <tr><td>Duration</td><td>${duration} seconds</td></tr>
    <tr><td>CLEF Version</td><td>${VERSION}</td></tr>
    <tr><td>Mode</td><td>$([ "${FAST_MODE}" -eq 1 ] && echo '<span class="badge warn">FAST (no file scan)</span>' || echo '<span class="badge ok">FULL</span>')</td></tr>
    <tr><td>Collection Dir</td><td>${DIRNAME}</td></tr>
  </table>
</div>

<div class="section">
  <h2>Collected Evidence Categories</h2>
  <table>
    <tr><th>Category</th><th>Directory</th><th>Status</th></tr>
    <tr><td>Commands &amp; Aliases</td><td>commands/</td><td><span class="badge ok">OK</span></td></tr>
    $([ "${FAST_MODE}" -eq 0 ] && echo '<tr><td>File System</td><td>files/</td><td><span class="badge ok">OK</span></td></tr>')
    $([ "${FAST_MODE}" -eq 0 ] && echo '<tr><td>Regex Matches</td><td>regex/</td><td><span class="badge ok">OK</span></td></tr>')
    <tr><td>Environment Variables</td><td>environment_vars/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Kernel Modules</td><td>modules/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>System Info</td><td>system/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Disks &amp; Mounts</td><td>disks/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Installed Packages</td><td>packages/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>User Accounts</td><td>accounts/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Running Processes</td><td>process/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Services</td><td>services/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Open Ports &amp; Connections</td><td>ports/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>ARP Cache</td><td>arp/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Network Traffic</td><td>traffic/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Network Interfaces</td><td>interfaces/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Scheduled Tasks</td><td>tasks/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Hardware</td><td>hardware/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Logs</td><td>logs/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Configurations</td><td>configurations/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Security Indicators</td><td>security/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Container Environment</td><td>containers/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Web Server Scripts</td><td>WebServerScripts/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Shell Histories</td><td>histories/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>Suspicious Files</td><td>suspicious/</td><td><span class="badge ok">OK</span></td></tr>
    <tr><td>System States</td><td>states/</td><td><span class="badge ok">OK</span></td></tr>
  </table>
</div>

<div class="section">
  <h2>Quick Indicators</h2>
  <table>
    <tr><th>Check</th><th>Count / Value</th></tr>
    <tr><td>SUID files</td><td>$(wc -l < "security/suid_files.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>SGID files</td><td>$(wc -l < "security/sgid_files.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>World-writable files</td><td>$(wc -l < "security/world_writable_files.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>Orphan files (no owner)</td><td>$(wc -l < "security/orphan_files.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>Executables in /tmp</td><td>$(wc -l < "security/tmp_executables.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>Recently modified system binaries</td><td>$(wc -l < "suspicious/recently_modified_binaries.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>Files with capabilities</td><td>$(wc -l < "security/file_capabilities.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>UID 0 accounts</td><td>$(wc -l < "accounts/uid0_accounts.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>Container type</td><td>$(cat "containers/container_type.txt" 2>/dev/null || echo "N/A")</td></tr>
    <tr><td>Private key files found</td><td>$(wc -l < "regex/private_key_files.txt" 2>/dev/null || echo "N/A")</td></tr>
  </table>
</div>

<div class="section">
  <h2>Log File</h2>
  <p>Detailed collection log: <code>../${DIRNAME}_LOG.csv</code></p>
</div>

<footer style="margin-top:40px;color:#555;font-size:0.8em;">
Generated by CLEF v${VERSION} &mdash; ${DESCRIPTION}
</footer>
</body>
</html>
HTML

    show_info "COLLECTED: HTML summary report" "OK" "${POURCENT}"
}

function do_help() {
    cat <<EOF
${DESCRIPTION}

USAGE: ${FILENAME} [-h] [-c] [-d] [-l] [-f] [-v]

OPTIONS:
  -h, --help       This help message
  -c, --no-color   Disable colors (useful for output redirection)
  -d, --no-debug   Disable interactive breakpoints
  -l, --no-logs    Disable CSV logging
  -f, --fast       Fast mode: skip full filesystem scan and regex matching
  -v, --version    Print version and exit

OUTPUT:
  <scriptname>_<YYYYMMDD_HHMMSS>/          Evidence directory
  <scriptname>_<YYYYMMDD_HHMMSS>_LOG.csv   Collection log
  <scriptname>_<YYYYMMDD_HHMMSS>.tar       Uncompressed archive
                                            (text files inside are gzip-compressed)
EOF
    trap - EXIT
    exit 1
}

function parse_args() {
    log_debug "Parsing arguments..."
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -f|--fast)
                FAST_MODE=1
                _ADD=5
                log_debug "Fast mode enabled"
                shift ;;
            -c|--no-color)
                COLOR=0
                log_debug "Colors disabled"
                shift ;;
            -d|--no-debug)
                DEBUG=0
                log_warning "Breakpoints disabled"
                shift ;;
            -l|--no-logs)
                LOG_LEVEL=51
                log_warning "Logging disabled"
                shift ;;
            -v|--version)
                echo "${FILENAME} ${VERSION}"
                trap - EXIT
                exit 0 ;;
            -h|--help|*)
                do_help ;;
        esac
    done
    log_debug "Arguments parsed."
}

function you_are_not_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_critical "Not running as root."
        show_info "Error: superuser privileges required." "ERROR"
        trap - EXIT
        exit 3
    fi
}

function on_error() {
    echo -e "\x1b[K"
    log_error "Unexpected error at line ${BASH_LINENO[0]}"
    BREAKPOINT "unexpected error"
    trap - EXIT
    exit 127
}

function on_ctrl_c() {
    echo -e "\x1b[K"
    log_warning "Interrupted by user (Ctrl+C)"
    BREAKPOINT "<Ctrl+C>"
    trap - EXIT
    exit 4
}

function build_archive() {
    show_info "Compressing text files and building archive..." "INFO" "${POURCENT}"

    gz_dir_text_files "${DIRNAME}"
    gz_text_file "${DIRNAME}/report.html"

    local archive="${LAUNCH_PWD}/${DIRNAME}.tar"
    tar -cf "${archive}" -C "${LAUNCH_PWD}" "${DIRNAME}"
    log_info "Archive created: ${archive}"
    show_info "Archive: ${archive}" "OK" "${POURCENT}"
}

function main() {
    trap on_error EXIT
    trap on_ctrl_c INT

    to_CSV "Date Time" "Log Level" "Filename" "PID" "Shell" "Localization" "Log Message" \
        > "${LOG_FILE}"
    log_debug "Logger initialised."

    echo "${COPYRIGHT}"
    echo '
 ░░░░░░ ░░      ░░░░░░░ ░░░░░░░
▒▒      ▒▒      ▒▒      ▒▒
▒▒      ▒▒      ▒▒▒▒▒   ▒▒▒▒▒
▓▓      ▓▓      ▓▓      ▓▓
 ██████ ███████ ███████ ██
'

    parse_args "$@"
    you_are_not_root

    mkdir "${DIRNAME}" && cd "${DIRNAME}"
    log_info "Evidence directory created: ${DIRNAME}"
    show_info "Starting evidence collection..." "INFO" "${POURCENT}"

    get_commands
    POURCENT=$(( POURCENT + _ADD ))

    if [[ "${FAST_MODE}" -eq 0 ]]; then
        show_info "Counting files..." "INFO" "${POURCENT}"
        TOTAL_FILE=$(find / \( -path /proc -o -path /sys \) -prune \
            -o -type f ! -type l -print 2>/dev/null | wc -l)
        ONE_POURCENT=$(( TOTAL_FILE / 40 + 1 ))
        log_info "Total files: ${TOTAL_FILE}, one pourcent: ${ONE_POURCENT}"
        get_files
        POURCENT=$(( POURCENT + _ADD ))
        get_regex_match
        POURCENT=$(( POURCENT + _ADD ))
    else
        show_info "Fast mode: skipping filesystem scan and regex matching." "NOK"
        log_warning "Fast mode: filesystem scan and regex matching skipped."
    fi

    for collector in \
        get_environment_vars \
        get_modules \
        get_system \
        get_disks \
        get_packages \
        get_accounts \
        get_process \
        get_services \
        get_opened_ports \
        get_arp_cache \
        get_network_traffic \
        get_network_interfaces \
        get_tasks \
        get_hardware \
        get_logs \
        get_configurations \
        get_security \
        get_containers \
        get_webserverscripts \
        get_histories \
        get_suspicious \
        get_states; do

        ${collector}
        POURCENT=$(( POURCENT + _ADD ))
    done

    generate_html_report

    cd "${LAUNCH_PWD}"
    build_archive

    show_info "All evidence collected successfully!" "OK" 100
    echo -e "\n"
    echo "Evidence directory : ${LAUNCH_PWD}/${DIRNAME}/"
    echo "Archive            : ${LAUNCH_PWD}/${DIRNAME}.tar"
    echo "Log file           : ${LOG_FILE}"

    trap - EXIT
    exit 0
}

export -f BREAKPOINT
main "$@"
