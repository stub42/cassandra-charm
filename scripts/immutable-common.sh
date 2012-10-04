: ${JUJU_UNIT_NAME?}
IMMUTABLE_VAR_STATE_DIR=/var/lib/juju/state
_immutable_get_filename() {
  local varname=${1:?missing varname}
  local unit_name=${JUJU_UNIT_NAME?}
  unit_name=${unit_name//\//-}
  local state_file_dir=${IMMUTABLE_VAR_STATE_DIR}/${unit_name}
  local state_file=${state_file_dir}/${varname}
  [[ -d ${state_file_dir} ]] || mkdir -p ${state_file_dir}
  echo ${state_file}
}
immutable_cleanup() {
  local dir=$(_immutable_get_filename "")
  case "${dir}" in
    /var/lib/juju/state/*) ;; ##ok
    *) juju-log "ERROR: invalid directory for cleanup: ${dir}"
       return 1;; 
  esac
  rm -rf ${dir?}/*
}
immutable_set() {
  local varname=${1:?missing varname}
  local new_value=${2:?missing new_value}
  local state_file=$(_immutable_get_filename "$1")
  local curr_value
  if [[ -f ${state_file} ]];then
    curr_value=$(immutable_get "$varname")
    if [[ curr_value != new_value ]];then
      juju-log "ERROR: tried to set immutable '$varname' from '$curr_value' -> '$new_value'"
      return 1
    fi
  else
    echo "${new_value}" > "${state_file}"
    juju-log "INFO: set immutable '$varname' to '$new_value' (${state_file})"
  fi
  return $?
}
immutable_get() {
  local varname=${1:?missing varname}
  local state_file=$(_immutable_get_filename "$varname")
  return $(<${state_file})
}
