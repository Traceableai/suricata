#!/bin/bash
set -x
echo "Killing any running suricata instance."
sudo kill `ps -ef | grep suricata | grep -v grep | grep -v build-suricata*sh | awk '{print $2}'`
echo "Install git."
sudo yum install -y git
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to install git."
  exit 1
fi
echo "Install development tools."
sudo yum groupinstall -y "Development Tools"
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to install development tools."
  exit 1
fi
echo "Install epel package repo."
sudo amazon-linux-extras install -y epel
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to setup epel repo package."
  exit 1
fi
echo "Install dependent packages."
sudo yum install -y pcre-devel \
  libyaml-devel \
  jansson-devel \
  libtool-ltdl \
  libpcap libpcap-devel \
  lz4 lz4-devel \
  libcap-ng-devel \
  file-devel
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to install packages."
  exit 1
fi
echo "Install rust."
sudo amazon-linux-extras install -y rust1
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to install rust1."
  exit 1
fi
echo "Install cbindgen."
mkdir -p /home/ec2-user/.cargo/
cat > /home/ec2-user/.cargo/config <<EOF
[net]
git-fetch-with-cli = true
EOF

cargo install --force cbindgen
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to install cbindgen."
  exit 1
fi
echo "Setting path to include cbindgen."
export PATH=/home/ec2-user/.cargo/bin:$PATH
echo "Cloning libhtp."
rm -Rf libhtp
git clone https://github.com/OISF/libhtp
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to clone libhtp"
  exit 1
fi
echo "Running autogen.sh"
./autogen.sh
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to run autogen.sh."
  exit 1
fi
echo "Running configure."
./configure
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to run configure."
  exit 1
fi
echo "Running make."
make
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to run make."
  exit 1
fi
echo "Running make install."
sudo make install
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to run make install"
  exit 1
fi
echo "Creating /usr/local/etc/suricata."
sudo mkdir -p /usr/local/etc/suricata
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to create /usr/local/etc/suricata."
  exit 1
fi
echo "Copying configuration details."
sudo cp -R config/* /usr/local/etc/suricata
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to copy configuration to /usr/local/etc/suricata."
  exit 1
fi
echo "Creating /usr/local/var/run/suricata."
sudo mkdir -p /usr/local/var/run/suricata/
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to create suricta."
  exit 1
fi
sudo mkdir -p /usr/local/var/log/suricata
rc=$?
if [ $rc -ne 0 ];
then
  echo "Failed to create /usr/local/var/log/suricata."
  exit 1
fi

sudo cp suricata.service /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable suricata.service
sudo systemctl start suricata.service

