# chip-tool

## Building Matter

- [Building Matter — Matter documentation](https://project-chip.github.io/connectedhomeip-doc/guides/BUILDING.html)

### Checking out the Matter code
```
export CHIP_TOOL_VER=1.5.0.1
git clone https://github.com/project-chip/connectedhomeip -b v${CHIP_TOOL_VER} --depth 1 --recurse-submodules connectedhomeip_${CHIP_TOOL_VER}
```
### Prerequisites

```
sudo apt update
sudo apt-get install -y git gcc g++ pkg-config cmake libssl-dev libdbus-1-dev \
     libglib2.0-dev libavahi-client-dev ninja-build python3-venv python3-dev \
     python3-pip unzip libgirepository1.0-dev libcairo2-dev libreadline-dev \
     default-jre
```

### Prepare for building

```
cd connectedhomeip_${CHIP_TOOL_VER}
source scripts/activate.sh
```

### Build for the host OS (Linux or macOS)

```
source scripts/activate.sh
gn gen out/host
ninja -C out/host
```

## References

- [project-chip/connectedhomeip: Matter (formerly Project CHIP)](https://github.com/project-chip/connectedhomeip)
- [Welcome to Matter’s documentation — Matter documentation](https://project-chip.github.io/connectedhomeip-doc/index.html)
