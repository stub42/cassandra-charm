# juju storage common shell library

#------------------------------
# Returns a mount point from passed vol-id, e.g. /srv/juju/vol-000012345
#
# @param  $1 volume id
# @return    mount point path, eg /srv/juju/vol-000012345
#------------------------------
mntpoint_from_volid() {
  local volid=${1?missing volid}
  [[ ${volid} != "" ]] && echo /srv/juju/${volid} || echo ""
}

#------------------------------
# Initialize volume (sfdisk, mkfs.ext4) IFF NOT already, mount it at
# /srv/juju/<volume-id>
#
# @param  $1 volume-id, can be any arbitrary string, better if
#            equal to EC2/OS vol-id name (just for consistency)
# @param  $2 device regexp, eg /dev/vd? - the top reverse sorted
#            unused will be used
# @return  0 success
#          1 nil volid/etc
#          2 error while handling the device (non-block device, sfdisk error, etc)
# @calls   mntpoint_from_volid()
#------------------------------
volume_init_and_mount() {
  ## Find 1st unused device (reverse sort /dev/vdX)
  local volid=${1:?missing volid}
  local dev_regexp=$(config-get volume-dev_regexp)
  local dev found_dev=
  local mntpoint=$(mntpoint_from_volid ${volid})
  local label="${volid}"
  local func=${FUNCNAME[0]}

  [[ -z ${mntpoint} ]] && return 1

  # Assume udev will create only existing devices
  for dev in $(ls -r ${dev_regexp} 2>/dev/null);do
    ## Check it's not already mounted
    mount | fgrep -q "${dev}[1-9]?" || { found_dev=${dev}; break;}
  done
  [[ -n "${found_dev}" ]] || {
    juju-log "ERROR: ${func}: coult not find an unused for: ${dev_regexp}"
    return 1
  }
  partition1_dev=${found_dev}1

  juju-log "INFO: ${func}: found_dev=${found_dev}"
  [[ -b ${found_dev?}  ]] || {
    juju-log "ERROR: ${func}: ${found_dev} is not a blockdevice"
    return 2
  }

  # Run next set of "dangerous" commands as 'set -e', in a subshell
  (
  set -e
  # Re-read partition - will fail if already in use
  blockdev --rereadpt ${found_dev}

  # IFF not present, create partition with full disk
  if [[ -b ${partition1_dev?} ]];then
    juju-log "INFO: ${func}: ${partition1_dev} already present - skipping sfdisk."
  else
    juju-log "NOTICE: ${func}: ${partition1_dev} not present at ${found_dev}, running: sfdisk ${found_dev} ..."
    # Format partition1_dev as max sized
    echo ",+," | sfdisk ${found_dev}
  fi

  # Create an ext4 filesystem if NOT already present
  # use e.g. LABEl=vol-000012345
  if file -s ${partition1_dev} | egrep -q ext4 ; then
    juju-log "INFO: ${func}: ${partition1_dev} already formatted as ext4 - skipping mkfs.ext4."
  else
    juju-log "NOTICE: ${func}: running: mkfs.ext4 -L ${label} ${partition1_dev}"
    mkfs.ext4 -L "${label}" ${partition1_dev}
  fi

  # Mount it at e.g. /srv/juju/vol-000012345
  [[ -d "${mntpoint}" ]] || mkdir -p "${mntpoint}"
  mount | fgrep -wq "${partition1_dev}" || {
    mount -L "${label}" "${mntpoint}"
    juju-log "INFO: ${func}: mounted as: $(mount | fgrep -w ${found_dev})"
  }

  # Add it to fstab is not already there
  fgrep -wq "LABEL=${label}" /etc/fstab || {
    echo "LABEL=${label}    ${mntpoint}    auto    defaults,nobootwait,comment=${volid}" | tee -a /etc/fstab
    juju-log "INFO: ${func}: LABEL=${label} added to /etc/fstab"
  }
  )
  return $?
}

#------------------------------
# Get volume-id from juju config "volume-map" dictionary as
#   volume-map[JUJU_UNIT_NAME]
# @return  volid or "" (echoed)
#------------------------------
volid_config_get() {
  local volid=$(config-get "volume-map"|python -c$'import sys;import os;from yaml import load;from itertools import chain; volume_map = load(sys.stdin)\nif volume_map: print volume_map.get(os.environ["JUJU_UNIT_NAME"])')
  [[ $volid == None ]] && return 1
  echo "$volid"
}

# Do we have a valid storage state?
# @returns  0 does echo $volid (can be "--ephemeral")
#           1 config state is invalid - we should not serve
storage_config() {
  local EPHEMERAL_STORAGE=$(config-get ephemeral-storage)
  local volid=$(volid_config_get)
  if [[ $EPHEMERAL_STORAGE == True ]];then
    # Ephemeral -> should not have a valid volid
    if [[ $volid != "" ]];then
        juju-log "ERROR: ephemeral-storage is True, but $JUJU_UNIT_NAME maps to volid=${volid}"
        return 1
    fi
  else
    # Durable (not ephemeral) -> must have a valid volid
     if [[ $volid == "" ]];then
        juju-log "ERROR: ephemeral-storage is False, but no volid found for: $JUJU_UNIT_NAME"
        return 1
     fi
  fi
  echo "$volid"
  return 0
}
