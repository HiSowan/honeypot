#!/usr/bin/env bash
set -e
COWRIE_DIR=/home/cowrie/cowrie
sudo -u cowrie sh -c "
  cd $COWRIE_DIR
  cowrie-env/bin/twistd \
    --umask=0022 \
    --pidfile var/run/cowrie.pid \
    -l var/log/cowrie/cowrie.log \
    cowrie
"
echo "Cowrie started."
