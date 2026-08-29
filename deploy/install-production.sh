#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer with sudo." >&2
    exit 1
fi

source_dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
source_dir="$(cd "${source_dir}" && pwd -P)"
install_root="/opt/sshguard"
release_root="${install_root}/releases"
state_dir="/var/lib/sshguard"
log_dir="/var/log/sshguard"
backup_root="/var/backups/sshguard"
service_group="mc"

if [[ "${source_dir}" == "/" || "${source_dir}" == "${install_root}"* ]]; then
    echo "Refusing unsafe source directory: ${source_dir}" >&2
    exit 1
fi

for required_path in \
    "${source_dir}/.git" \
    "${source_dir}/main.py" \
    "${source_dir}/requirements-dashboard.txt" \
    "${source_dir}/dashboard/web/dist/index.html"; do
    if [[ ! -e "${required_path}" ]]; then
        echo "Required deployment input is missing: ${required_path}" >&2
        exit 1
    fi
done

if ! getent group "${service_group}" >/dev/null; then
    echo "Service group does not exist: ${service_group}" >&2
    exit 1
fi

if ! git -C "${source_dir}" diff --quiet || \
   ! git -C "${source_dir}" diff --cached --quiet; then
    echo "Tracked files must be committed before production deployment." >&2
    exit 1
fi

revision="$(git -C "${source_dir}" rev-parse --verify HEAD)"
release_id="$(date -u +%Y%m%dT%H%M%SZ)-${revision:0:12}"
release_dir="${release_root}/${release_id}"
stage_dir=""

cleanup_stage() {
    if [[ -n "${stage_dir}" && -d "${stage_dir}" ]]; then
        resolved_stage="$(readlink -f "${stage_dir}")"

        if [[ "${resolved_stage}" == "${release_root}/.stage."* ]]; then
            rm -rf -- "${resolved_stage}"
        fi
    fi
}

trap cleanup_stage EXIT

install -d -o root -g root -m 0755 "${install_root}" "${release_root}"
stage_dir="$(mktemp -d "${release_root}/.stage.XXXXXX")"

GIT_NO_REPLACE_OBJECTS=1 git -C "${source_dir}" \
    archive --format=tar "${revision}" | \
    tar -xf - -C "${stage_dir}"

if find "${stage_dir}" -type l -print -quit | grep -q .; then
    echo "Committed production source must not contain symlinks." >&2
    exit 1
fi

if find "${source_dir}/dashboard/web/dist" \
    -type l -print -quit | grep -q .; then
    echo "Built dashboard must not contain symlinks." >&2
    exit 1
fi

install -d -o root -g root -m 0755 "${stage_dir}/dashboard/web/dist"
cp -a "${source_dir}/dashboard/web/dist/." "${stage_dir}/dashboard/web/dist/"

if find "${stage_dir}/dashboard/web/dist" \
    -type l -print -quit | grep -q .; then
    echo "Copied dashboard must not contain symlinks." >&2
    exit 1
fi

chown -R root:root "${stage_dir}"
chmod -R go-w "${stage_dir}"
mv "${stage_dir}" "${release_dir}"
stage_dir=""

python3 -m venv "${release_dir}/.venv"
"${release_dir}/.venv/bin/python" -m pip install \
    --disable-pip-version-check \
    -r "${release_dir}/requirements-dashboard.txt"

"${release_dir}/.venv/bin/python" \
    -W error::ResourceWarning \
    -m unittest discover \
    -s "${release_dir}/tests" \
    -t "${release_dir}" \
    -v

chown -R root:root "${release_dir}"
chmod -R go-w "${release_dir}"

install -d -o root -g "${service_group}" -m 0750 \
    "${state_dir}" "${log_dir}"
install -d -o root -g root -m 0750 "${backup_root}"

stop_service_if_loaded() {
    service_name="$1"

    if systemctl cat "${service_name}" >/dev/null 2>&1; then
        systemctl stop "${service_name}"
    fi
}

stop_service_if_loaded sshguard-dashboard-api.service
stop_service_if_loaded sshguard-project.service

backup_dir="${backup_root}/${release_id}"
install -d -o root -g root -m 0750 "${backup_dir}"

for unit_name in sshguard-project.service sshguard-dashboard-api.service; do
    installed_unit="/etc/systemd/system/${unit_name}"

    if [[ -f "${installed_unit}" ]]; then
        cp -a "${installed_unit}" "${backup_dir}/${unit_name}"
    fi
done

legacy_database="${source_dir}/data/sshguard.db"
production_database="${state_dir}/sshguard.db"

if [[ -f "${production_database}" ]]; then
    sqlite3 "${production_database}" \
        ".backup '${backup_dir}/sshguard.db'"
elif [[ -f "${legacy_database}" ]]; then
    sqlite3 "${legacy_database}" \
        ".backup '${production_database}'"
fi

legacy_log="${source_dir}/logs/sshguard.log"
production_log="${log_dir}/sshguard.log"

if [[ -f "${production_log}" ]]; then
    cp -a "${production_log}" "${backup_dir}/sshguard.log"
elif [[ -f "${legacy_log}" ]]; then
    install -o root -g "${service_group}" -m 0640 \
        "${legacy_log}" "${production_log}"
fi

if [[ -f "${production_database}" ]]; then
    chown root:"${service_group}" "${production_database}"
    chmod 0640 "${production_database}"
fi

if [[ -f "${production_log}" ]]; then
    chown root:"${service_group}" "${production_log}"
    chmod 0640 "${production_log}"
fi

new_link="${install_root}/.current-${release_id}"
ln -s "releases/${release_id}" "${new_link}"
mv -Tf "${new_link}" "${install_root}/current"

install -o root -g root -m 0644 \
    "${release_dir}/deploy/sshguard-project.service" \
    /etc/systemd/system/sshguard-project.service
install -o root -g root -m 0644 \
    "${release_dir}/deploy/sshguard-dashboard-api.service" \
    /etc/systemd/system/sshguard-dashboard-api.service

systemctl daemon-reload
systemd-analyze verify \
    /etc/systemd/system/sshguard-project.service \
    /etc/systemd/system/sshguard-dashboard-api.service
systemctl enable \
    sshguard-project.service \
    sshguard-dashboard-api.service
systemctl start sshguard-project.service
systemctl start sshguard-dashboard-api.service

health_url="http://127.0.0.1:8000/api/v1/health"

for attempt in {1..20}; do
    if curl --fail --silent --show-error "${health_url}"; then
        break
    fi

    if [[ "${attempt}" -eq 20 ]]; then
        echo "Dashboard health check failed: ${health_url}" >&2
        exit 1
    fi

    sleep 0.5
done

echo
systemctl is-active \
    sshguard-project.service \
    sshguard-dashboard-api.service
sqlite3 "${production_database}" "PRAGMA integrity_check;"
echo "Activated SSHGuard release: ${release_id}"
echo "Preserved deployment backup: ${backup_dir}"
