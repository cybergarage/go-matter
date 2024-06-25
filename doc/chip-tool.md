## Build the chip-tool

```
sudo apt-get install -y git gcc g++ pkg-config libssl-dev libdbus-1-dev libglib2.0-dev libavahi-client-dev ninja-build python3-venv python3-dev python3-pip unzip libgirepository1.0-dev libcairo2-dev libreadline-dev 
git clone https://github.com/project-chip/connectedhomeip -b v1.3.0.0 --depth 1 --recurse-submodules connectedhomeip_v1.3.0.0
cd connectedhomeip_v1.3.0.0
./scripts/examples/gn_build_example.sh examples/chip-tool $PWD/out/linux
```

## Setup 

```
export SSID=
export PASS=
export MPC=
```

```
cd out/linux/chip-tool
./chip-tool pairing code-wifi 1 $SSID $PASS $MPC
./chip-tool pairing code-wifi 1 $SSID $PASS $MPC --paa-trust-store-path  ../../credentials/production/paa-root-certs 
```
