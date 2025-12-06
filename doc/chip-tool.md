# chip-tool

## Building Matter

- [Welcome to Matter’s documentation — Matter documentation](https://project-chip.github.io/connectedhomeip-doc/index.html)
  - [Building Matter — Matter documentation](https://project-chip.github.io/connectedhomeip-doc/guides/BUILDING.htm)

### Checking out the Matter code
```
export CHIP_TOOL_VER=1.5.0.1
git clone https://github.com/project-chip/connectedhomeip -b v${CHIP_TOOL_VER} --depth 1 --recurse-submodules connectedhomeip_${CHIP_TOOL_VER}
```
### Prerequisites

```
sudo apt-get install git gcc g++ pkg-config cmake libssl-dev libdbus-1-dev \
     libglib2.0-dev libavahi-client-dev ninja-build python3-venv python3-dev \
     python3-pip unzip libgirepository1.0-dev libcairo2-dev libreadline-dev \
     default-jre
```

### Prepare for building

## References

- [project-chip/connectedhomeip: Matter (formerly Project CHIP)](https://github.com/project-chip/connectedhomeip)

