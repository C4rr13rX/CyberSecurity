#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 <block-device> [workdir] [--include-tor]

Creates a bootable Linux environment on the target USB device with the
paranoid_av binary and an autorun service that performs system, rootkit, and
process scans at boot.

Environment variables:
  PARANOID_AV_BIN   Path to the compiled paranoid_av binary. Defaults to
                    ../build/paranoid_av relative to this script.
USAGE
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "[!] This helper must run as root." >&2
    exit 1
  fi
}

resolve_binary() {
  local script_dir
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  local default_bin="${script_dir}/../build/paranoid_av"
  if [[ -n "${PARANOID_AV_BIN:-}" ]]; then
    echo "${PARANOID_AV_BIN}"
    return
  fi
  if [[ -x "${default_bin}" ]]; then
    echo "${default_bin}"
    return
  fi
  echo "[!] paranoid_av binary not found. Set PARANOID_AV_BIN or build the project." >&2
  exit 1
}

check_dependencies() {
  local deps=(debootstrap grub-install parted mkfs.ext4 wipefs lsblk mount umount blkid chroot sed tee)
  for dep in "${deps[@]}"; do
    if ! command -v "${dep}" >/dev/null 2>&1; then
      echo "[!] Required dependency '${dep}' missing." >&2
      exit 1
    fi
  done
}

unmount_partitions() {
  local device=$1
  while read -r mountpoint; do
    if [[ -n "${mountpoint}" ]]; then
      umount -lf "${mountpoint}" || true
    fi
  done < <(lsblk -nrpo MOUNTPOINT "${device}" | grep -v '^$' || true)
}

create_partition() {
  local device=$1
  wipefs -a "${device}"
  parted --script "${device}" mklabel gpt
  parted --script "${device}" mkpart primary ext4 1MiB 100%
  parted --script "${device}" set 1 boot on
  lsblk -nrpo NAME "${device}" | tail -n1
}

prepare_rootfs() {
  local partition=$1
  local mountpoint=$2
  local suite=${DEBIAN_SUITE:-bookworm}
  mkfs.ext4 -F "${partition}"
  mkdir -p "${mountpoint}"
  mount "${partition}" "${mountpoint}"
  debootstrap --arch=amd64 --variant=minbase     --include=linux-image-amd64,grub-pc,systemd-sysv,network-manager,openssh-client,curl,ca-certificates     "${suite}" "${mountpoint}" http://deb.debian.org/debian
}

configure_rootfs() {
  local mountpoint=$1
  local binary=$2
  local partition=$3

  install -Dm755 "${binary}" "${mountpoint}/usr/local/bin/paranoid_av"

  cat <<'SCRIPT' > "${mountpoint}/usr/local/sbin/paranoid-usb-scan.sh"
#!/usr/bin/env bash
set -euo pipefail
LOG=/var/log/paranoid-usb-scan.log
exec >>"${LOG}" 2>&1

echo "=== Paranoid USB scan $(date -Is) ==="
if command -v freshclam >/dev/null 2>&1; then
  freshclam || true
fi
paranoid_av --system-audit || true
paranoid_av --rootkit-scan --json || true
paranoid_av --monitor --json || true
echo "=== Scan completed $(date -Is) ==="
SCRIPT
  chmod +x "${mountpoint}/usr/local/sbin/paranoid-usb-scan.sh"

  cat <<'SERVICE' > "${mountpoint}/etc/systemd/system/paranoid-usb-scan.service"
[Unit]
Description=Paranoid USB Auto Scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/paranoid-usb-scan.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

  mkdir -p "${mountpoint}/etc/systemd/system/multi-user.target.wants"
  ln -sf ../paranoid-usb-scan.service "${mountpoint}/etc/systemd/system/multi-user.target.wants/paranoid-usb-scan.service"

  local uuid
  uuid=$(blkid -s UUID -o value "${partition}")
  cat <<EOF > "${mountpoint}/etc/fstab"
UUID=${uuid} / ext4 defaults 0 1
EOF

  cat <<'ISSUE' > "${mountpoint}/etc/issue"
Paranoid USB Scanner
Log in as root (no password) for recovery. Scans run automatically at boot.
ISSUE
}

bind_mounts() {
  local mountpoint=$1
  mount --bind /dev "${mountpoint}/dev"
  mount --bind /dev/pts "${mountpoint}/dev/pts"
  mount --bind /proc "${mountpoint}/proc"
  mount --bind /sys "${mountpoint}/sys"
}

finalise_rootfs() {
  local mountpoint=$1
  local include_tor=$2
  if [[ -f "${mountpoint}/etc/shadow" ]]; then
    sed -i 's/^root:[^:]*:/root::/' "${mountpoint}/etc/shadow"
  fi
  if [[ "${include_tor}" == "1" ]]; then
    chroot "${mountpoint}" apt-get update
    chroot "${mountpoint}" apt-get install -y --no-install-recommends tor nyx || true
  fi
}

install_bootloader() {
  local device=$1
  local mountpoint=$2
  chroot "${mountpoint}" grub-install "${device}"
  chroot "${mountpoint}" update-grub
}

cleanup_mounts() {
  local mountpoint=$1
  for target in dev/pts dev proc sys; do
    if mountpoint -q "${mountpoint}/${target}"; then
      umount "${mountpoint}/${target}" || true
    fi
  done
  if mountpoint -q "${mountpoint}"; then
    umount "${mountpoint}" || true
  fi
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  local device=""
  local workdir=""
  local include_tor=0

  for arg in "$@"; do
    case "${arg}" in
      --include-tor)
        include_tor=1
        ;;
      *)
        if [[ -z "${device}" ]]; then
          device="${arg}"
        elif [[ -z "${workdir}" ]]; then
          workdir="${arg}"
        else
          echo "[!] Unexpected argument '${arg}'." >&2
          exit 1
        fi
        ;;
    esac
  done

  if [[ -z "${device}" ]]; then
    usage
    exit 1
  fi

  if [[ ! -b "${device}" ]]; then
    echo "[!] ${device} is not a block device." >&2
    exit 1
  fi

  workdir=${workdir:-/tmp/paranoid-usb}
  mkdir -p "${workdir}"
  local mountpoint="${workdir}/rootfs"
  local binary
  binary=$(resolve_binary)

  require_root
  check_dependencies
  echo "[*] Preparing USB scanner on ${device} using staging ${workdir}" >&2

  unmount_partitions "${device}"
  local partition
  partition=$(create_partition "${device}")
  echo "[*] Created partition ${partition}" >&2

  prepare_rootfs "${partition}" "${mountpoint}"
  configure_rootfs "${mountpoint}" "${binary}" "${partition}"

  bind_mounts "${mountpoint}"
  trap 'cleanup_mounts "${mountpoint}"' EXIT
  finalise_rootfs "${mountpoint}" "${include_tor}"
  install_bootloader "${device}" "${mountpoint}"
  cleanup_mounts "${mountpoint}"
  trap - EXIT

  sync
  echo "[+] USB scanner created successfully on ${device}."
}

main "$@"
