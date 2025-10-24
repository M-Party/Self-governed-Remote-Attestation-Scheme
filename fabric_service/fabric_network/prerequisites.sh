#!/bin/bash

# Define those global variables
if [ -f ./variables.sh ]; then
 source ./variables.sh
elif [ -f ./scripts/variables.sh ]; then
 source ./scripts/variables.sh
else
    echo "Cannot find the variables.sh files, pls check"
    exit 1
fi

# Download binaries
./download.sh ${HLF_VERSION} -d -s
rm -rf config/

# Generate crypto-config for relying parties
bin/cryptogen generate \
    --config fixtures/network/crypto-config.yaml \
    --output fixtures/network/crypto-config

# Rename private key's name
mv fixtures/network/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/*_sk fixtures/network/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/keystore/priv_sk

# Generate genesis block file
if [ ! -d fixtures/network/${CHANNEL_ARTIFACTS} ]; then
    mkdir fixtures/network/${CHANNEL_ARTIFACTS}
fi

echo "Generate genesis block for system channel using configtx.yaml"

bin/configtxgen \
    -configPath fixtures/network \
    -channelID ${SYS_CHANNEL} \
    -profile ${ORDERER_GENSIS_PROFILE} \
    -outputBlock fixtures/network/${CHANNEL_ARTIFACTS}/${ORDERER_GENSIS}

# NEW NEW NEW
# Generate channel configuration transaction file
# 清理并重建目录
rm -rf fixtures/network/crypto-config fixtures/network/channel-artifacts
mkdir -p fixtures/network/crypto-config fixtures/network/channel-artifacts

# 生成证书
./bin/cryptogen generate \
  --config=fixtures/network/crypto-config.yaml \
  --output=fixtures/network/crypto-config

# 生成创世块和通道 TX
export FABRIC_CFG_PATH="$(pwd)/fixtures/network"
./bin/configtxgen -profile TwoOrgsOrdererGenesis \
  -channelID byfn-sys-channel \
  -outputBlock fixtures/network/channel-artifacts/orderer.genesis.block

./bin/configtxgen -profile TwoOrgsChannel \
  -channelID mychannel \
  -outputCreateChannelTx fixtures/network/channel-artifacts/mychannel.tx