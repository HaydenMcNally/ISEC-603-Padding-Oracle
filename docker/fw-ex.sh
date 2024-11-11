#!/bin/bash

if [[ "$1" == '1' ]]; then
  echo "ex-1 specified"
  EXFILE="fw-1"
elif [[ "$1" == '2' ]]; then
  echo "ex-2 specified"
  EXFILE="fw-2"
else
  echo "either of 1 (for ex-1) or 2 (for ex-2) needs to be specified; exiting"
  exit
fi

if [[ "$2" == 'build' ]]; then
  echo "build arg specified. will attempt to build containers"
  YAMLFILE="$(pwd)/${EXFILE}-build.yml"
else
  echo "release build.. will download from container registry.."
  YAMLFILE="$(pwd)/${EXFILE}.yml"
fi
if [ -f "$YAMLFILE" ]; then
  echo "$YAMLFILE exists."
else
  echo "${YAMLFILE} does not exists; exiting"
  exit
fi

# ------------

add_config_ex2() {
  echo "[+] inserting ssh config for ex-2"
  echo "-----------"
  FILE=~/.ssh/config
  if [ -f "$FILE" ]; then
    echo "[+] ${FILE} exists. Adding hosts ip to ssh config"
  else
    echo "${FILE} does not exists; creating.."
    mkdir -p ~/.ssh
    touch ${FILE}
  fi
  echo "[+] WARNING: attempting to add to host machine's ${FILE}.."
  LINE='\nHost kali.ex2\nHostName 10.29.107.5\nUser user\nStrictHostKeyChecking no\n'
  grep -qF -- "kali.ex2" "$FILE" || echo -e "$LINE" >>"$FILE"

  LINE='\nHost router.ex2\nHostName 10.29.107.11\nUser employee\nStrictHostKeyChecking no\n'
  grep -qF -- "router.ex2" "$FILE" || echo -e "$LINE" >>"$FILE"

  LINE='\nHost host1.ex2\nHostName 192.168.90.5\nUser employee\nStrictHostKeyChecking no\n'
  grep -qF -- "host1.ex2" "$FILE" || echo -e "$LINE" >>"$FILE"

  LINE='\nHost host2.ex2\nHostName 192.168.90.6\nUser employee\nStrictHostKeyChecking no\n'
  grep -qF -- "host2.ex2" "$FILE" || echo -e "$LINE" >>"$FILE"
  echo "[+] done!"
  echo "-----------"
}

add_config_ex1() {
  echo "[+] inserting ssh config for ex-1"
  echo "-----------"
  FILE=~/.ssh/config
  if [ -f "$FILE" ]; then
    echo "[+] ${FILE} exists. Adding hosts ip to ssh config"
  else
    echo "${FILE} does not exists; creating.."
    mkdir -p ~/.ssh
    touch ${FILE}
  fi
  echo "[+] WARNING: attempting to add to host machine's ${FILE}.."
  LINE='\n\nHost router.ex1\nHostName 10.50.107.11\nUser employee\nStrictHostKeyChecking no\n\n'
  grep -qF -- "router.ex1" "$FILE" || echo -e "$LINE" >>"$FILE"
  echo "[+] done!"
  echo "-----------"
}

docker_setup() {
  # add default platform; export DOCKER_DEFAULT_PLATFORM=linux/amd64
  DOCKERLINE="export DOCKER_DEFAULT_PLATFORM=linux/amd64"
  FILE=~/.bashrc
  grep -qF -- "$DOCKERLINE" "$FILE" || echo "$DOCKERLINE" >>"$FILE"
  BASE_FILE="/etc/bash.bashrc"
  ROOT_FILE="/root/.bashrc"
  sudo -s <<EOF
echo "------------------------------------"
echo "running as root"
echo "------------------------------------"
DOCKERLINE="export DOCKER_DEFAULT_PLATFORM=linux/amd64"
echo "adding $DOCKERLINE to $BASE_FILE"
grep -qF -- "$DOCKERLINE" "$BASE_FILE" || echo "$DOCKERLINE" >> "$BASE_FILE"
source $BASE_FILE
echo "adding $DOCKERLINE to $ROOT_FILE"
grep -qF -- "$DOCKERLINE" "$ROOT_FILE" || echo "$DOCKERLINE" >> "$ROOT_FILE"
source $ROOT_FILE
if [[ "$?" != 0 ]]; then
  echo "[-] error in adding default docker platform"
  exit 1
fi
EOF
  echo "[+] added default docker platform"
  source $FILE
}

add_alias() {
  # add alias for docker
  # docker_setup
  # adding alias for ssh.
  FILE=~/.bashrc
  LINE="alias ssh='ssh -F ~/.ssh/config'"
  grep -qF -- "$LINE" "$FILE" || echo "$LINE" >>"$FILE"
  # add alias for scp
  # LINE="alias scp='scp -F ~/.ssh/config'"
  # grep -qF -- "$LINE" "$FILE" || echo "$LINE" >> "$FILE"
  source ~/.bashrc
}

add_alias
if [[ "$1" == '1' ]]; then
  add_config_ex1
else
  add_config_ex2
fi
echo "[+] pruning previous machines.. please wait."
sudo docker ps -aq | xargs sudo docker stop | xargs sudo docker rm
sudo docker network prune -f
sudo docker compose -f ${YAMLFILE} down --remove-orphans
sudo docker compose -f ${YAMLFILE} stop
echo "[+] done! spinning up virtual machines/containers."
if [[ "$2" == 'build' ]]; then
  sudo docker compose -f ${YAMLFILE} build --pull
else
  sudo docker compose -f ${YAMLFILE} pull
fi
sudo docker compose -f ${YAMLFILE} up
