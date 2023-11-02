import { expect } from "chai";
import { ethers } from "hardhat";
import * as mcl from "../../ts/mcl";
import { MerkleTree } from "merkletreejs";
import { BLS, BN256G2, CheckpointManager } from "../../typechain-types";

const DOMAIN = ethers.utils.arrayify(ethers.utils.solidityKeccak256(["string"], ["DOMAIN_CHECKPOINT_MANAGER"]));

describe("CheckpointManager", () => {
  let bls: BLS,
    bn256G2: BN256G2,
    checkpointManager: CheckpointManager,
    submitCounter: number,
    validatorSetSize: number,
    validatorSecretKeys: any[],
    validatorSet: any[],
    accounts: any[]; // we use any so we can access address directly from object
  const chainId = 12345;
  before(async () => {
    await mcl.init();
    accounts = await ethers.getSigners();

    const BLS = await ethers.getContractFactory("BLS");
    bls = (await BLS.deploy()) as BLS;
    await bls.deployed();

    const BN256G2 = await ethers.getContractFactory("BN256G2");
    bn256G2 = (await BN256G2.deploy()) as BN256G2;
    await bn256G2.deployed();

    const CheckpointManager = await ethers.getContractFactory("CheckpointManager");
    checkpointManager = (await CheckpointManager.deploy(ethers.constants.AddressZero)) as CheckpointManager;
    await checkpointManager.deployed();
  });

  it("Initialize failed by zero voting power", async () => {
    validatorSetSize = Math.floor(Math.random() * (5 - 1) + 8); // Randomly pick 8 - 12

    validatorSecretKeys = [];
    validatorSet = [];
    for (let i = 0; i < validatorSetSize; i++) {
      const { pubkey, secret } = mcl.newKeyPair();
      validatorSecretKeys.push(secret);
      validatorSet.push({
        _address: accounts[i].address,
        blsKey: mcl.g2ToHex(pubkey),
        votingPower: 0,
      });
    }

    await expect(checkpointManager.initialize(bls.address, bn256G2.address, chainId, validatorSet)).to.be.revertedWith(
      "VOTING_POWER_ZERO"
    );
  });

  it("Initialize and validate initialization", async () => {
    validatorSetSize = Math.floor(Math.random() * (5 - 1) + 8); // Randomly pick 8 - 12

    validatorSecretKeys = [];
    validatorSet = [];
    for (let i = 0; i < validatorSetSize; i++) {
      const { pubkey, secret } = mcl.newKeyPair();
      validatorSecretKeys.push(secret);
      validatorSet.push({
        _address: accounts[i].address,
        blsKey: mcl.g2ToHex(pubkey),
        votingPower: ethers.utils.parseEther(((i + 1) * 2).toString()),
      });
    }

    await checkpointManager.initialize(bls.address, bn256G2.address, chainId, validatorSet);
    expect(await checkpointManager.bls()).to.equal(bls.address);
    expect(await checkpointManager.bn256G2()).to.equal(bn256G2.address);
    expect(await checkpointManager.currentValidatorSetLength()).to.equal(validatorSetSize);

    for (let i = 0; i < validatorSetSize; i++) {
      const validator = await checkpointManager.currentValidatorSet(i);
      expect(validator._address).to.equal(accounts[i].address);
      expect(validator.votingPower).to.equal(ethers.utils.parseEther(((i + 1) * 2).toString()));
    }

    const endBlock = (await checkpointManager.checkpoints(0)).blockNumber;
    expect(endBlock).to.equal(0);
    const prevId = await checkpointManager.currentEpoch();
    submitCounter = prevId.toNumber() + 1;
  });

  it("Submit checkpoint with invalid validator set hash", async () => {
    const chainId = submitCounter;
    const checkpoint = {
      epoch: 1,
      blockNumber: 0,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const bitmapStr = "ffff";

    const bitmap = `0x${bitmapStr}`;
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32"],
        [
          chainId + 1, //for signature verify fail
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    // // First feedInput
    // const feedInput1 = {
    //   blockNumber: 1,
    //   leafIndex: 0,
    //   unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
    //   proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    // };

    // // Second feedInput
    // const feedInput2 = {
    //   blockNumber: 2,
    //   leafIndex: 1,
    //   unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
    //   proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    // };

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];


    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("INVALID_VALIDATOR_SET_HASH");
  });

  it("Submit checkpoint with invalid signature", async () => {
    const checkpoint = {
      epoch: 1,
      blockNumber: 0,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmapStr = "ffff";

    const bitmap = `0x${bitmapStr}`;
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32"],
        [
          chainId + 1, //for signature verify fail
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];

    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("SIGNATURE_VERIFICATION_FAILED");
  });

  it("Submit checkpoint with empty bitmap", async () => {
    const checkpoint = {
      epoch: 1,
      blockNumber: 1,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmapStr = "00";

    const bitmap = `0x${bitmapStr}`;
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];

    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("BITMAP_IS_EMPTY");
  });

  it("Submit checkpoint with not enough voting power", async () => {
    const checkpoint = {
      epoch: 1,
      blockNumber: 1,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    
    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmapStr = "01";

    const bitmap = `0x${bitmapStr}`;
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));
    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("INSUFFICIENT_VOTING_POWER");
  });

  it("Submit checkpoint with invalid proof", async () => {
  
    const checkpoint = {
      epoch: 1,
      blockNumber: 1,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    // const bitmapNum = Math.floor(Math.random() * 0xffffffffffffffff);
    // let bitmapStr = bitmapNum.toString(16);
    // const length = bitmapStr.length;
    // for (let j = 0; j < 16 - length; j++) {
    //   bitmapStr = "0" + bitmapStr;
    // }

    // const bitmap = `0x${bitmapStr}`;
    const bitmap = "0xffff";
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("INVALID_PROOF");
  });

  it("Submit checkpoint success", async () => {

    const unhashedLeaf = ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")])

    const leaves = [
      ethers.utils.keccak256(unhashedLeaf),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    ];
    const tree = new MerkleTree(leaves, ethers.utils.keccak256);
    const leafIndex = 0;


    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: leafIndex,
      unhashedLeaf: unhashedLeaf,
      proof: tree.getHexProof(leaves[leafIndex]),
    }];

    const checkpoint = {
      epoch: 1,
      blockNumber: 1,
      eventRoot: tree.getHexRoot(),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmap = "0xffff";
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));


    await checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray);

    expect(await checkpointManager.getEventRootByBlock(checkpoint.blockNumber)).to.equal(checkpoint.eventRoot);
    expect(await checkpointManager.checkpointBlockNumbers(0)).to.equal(checkpoint.blockNumber);
    expect(await checkpointManager.getCheckpointBlock(1)).to.deep.equal([true, checkpoint.blockNumber]);
    expect(await checkpointManager.getCheckpointBlock(checkpoint.blockNumber + 1)).to.deep.equal([false, 0]);

    await checkpointManager.getEventMembershipByBlockNumber(
      checkpoint.blockNumber,
      checkpoint.eventRoot,
      leafIndex,
      tree.getHexProof(leaves[leafIndex])
    );
    await checkpointManager.getEventMembershipByEpoch(checkpoint.epoch, checkpoint.eventRoot, leafIndex, tree.getHexProof(leaves[leafIndex]));
  });

  it("Submit checkpoint with invalid epoch", async () => {
    const checkpoint = {
      epoch: 0,
      blockNumber: 0,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmapStr = "ffff";

    const bitmap = `0x${bitmapStr}`;
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );


    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("INVALID_EPOCH");
  });

  it("Submit checkpoint with empty checkpoint", async () => {
    const checkpoint = {
      epoch: 1,
      blockNumber: 0,
      eventRoot: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmapStr = "ffff";

    const bitmap = `0x${bitmapStr}`;
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: 0,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))],
    }, {
      blockNumber: 2,
      leafIndex: 1,
      unhashedLeaf: ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("1500")]),
      proof: [ethers.utils.hexlify(ethers.utils.randomBytes(32))], 
    }];

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );



    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    await expect(
      checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
    ).to.be.revertedWith("EMPTY_CHECKPOINT");
  });

  it("Submit checkpoint success with same epoch", async () => {

    const unhashedLeaf = ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [2, ethers.utils.parseEther("2000")])

    const leaves = [
      ethers.utils.keccak256(unhashedLeaf),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    ];
    const tree = new MerkleTree(leaves, ethers.utils.keccak256);
    const leafIndex = 0;

    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: leafIndex,
      unhashedLeaf: unhashedLeaf,
      proof: tree.getHexProof(leaves[leafIndex]),
    }];

    const checkpoint = {
      epoch: 1,
      blockNumber: 2,
      eventRoot: tree.getHexRoot(),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    // const bitmapNum = Math.floor(Math.random() * 0xffffffffffffffff);
    // let bitmapStr = bitmapNum.toString(16);
    // const length = bitmapStr.length;
    // for (let j = 0; j < 16 - length; j++) {
    //   bitmapStr = "0" + bitmapStr;
    // }

    // const bitmap = `0x${bitmapStr}`;
    const bitmap = "0xffff";
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );


    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(ethers.utils.formatEther(validatorSet[i].votingPower), 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    await checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray);

    expect(await checkpointManager.getEventRootByBlock(checkpoint.blockNumber)).to.equal(checkpoint.eventRoot);
    expect(await checkpointManager.checkpointBlockNumbers(0)).to.equal(checkpoint.blockNumber);
    expect(await checkpointManager.getCheckpointBlock(1)).to.deep.equal([true, checkpoint.blockNumber]);
    expect(await checkpointManager.getCheckpointBlock(checkpoint.blockNumber + 1)).to.deep.equal([false, 0]);

    // let proof = [];
    // proof.push(ethers.utils.hexlify(ethers.utils.randomBytes(32)));
    await checkpointManager.getEventMembershipByBlockNumber(
      checkpoint.blockNumber,
      checkpoint.eventRoot,
      leafIndex,
      tree.getHexProof(leaves[leafIndex])
    );
    await checkpointManager.getEventMembershipByEpoch(checkpoint.epoch, checkpoint.eventRoot, leafIndex, tree.getHexProof(leaves[leafIndex]));
  });

  it("Submit checkpoint success with short bitmap", async () => {

    const unhashedLeaf = ethers.utils.defaultAbiCoder.encode(["uint256", "uint256"], [1, ethers.utils.parseEther("1000")])

    const leaves = [
      ethers.utils.keccak256(unhashedLeaf),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ethers.utils.hexlify(ethers.utils.randomBytes(32)),
    ];
    const tree = new MerkleTree(leaves, ethers.utils.keccak256);
    const leafIndex = 0;


    const feedInputsArray = [{
      blockNumber: 1,
      leafIndex: leafIndex,
      unhashedLeaf: unhashedLeaf,
      proof: tree.getHexProof(leaves[leafIndex]),
    }];

    const checkpoint = {
      epoch: 2,
      blockNumber: 3,
      eventRoot: tree.getHexRoot(),
    };

    const checkpointMetadata = {
      blockHash: ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      blockRound: 0,
      currentValidatorSetHash: await checkpointManager.currentValidatorSetHash(),
    };

    const bitmap = "0xff";
    const messageOfValidatorSet = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(address _address, uint256[4] blsKey, uint256 votingPower)[]"],
        [validatorSet]
      )
    );

    const messageOfFeedInputs = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["tuple(uint256 blockNumber, uint256 leafIndex, bytes unhashedLeaf, bytes32[] proof)[]"],
        [feedInputsArray]
      )
    );

    const message = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["uint256", "uint256", "bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          chainId,
          checkpoint.blockNumber,
          checkpointMetadata.blockHash,
          checkpointMetadata.blockRound,
          checkpoint.epoch,
          checkpoint.eventRoot,
          checkpointMetadata.currentValidatorSetHash,
          messageOfFeedInputs,
          messageOfValidatorSet,
        ]
      )
    );

    const signatures: mcl.Signature[] = [];

    let aggVotingPower = 0;
    for (let i = 0; i < validatorSecretKeys.length; i++) {
      const byteNumber = Math.floor(i / 8);
      const bitNumber = i % 8;

      if (byteNumber >= bitmap.length / 2 - 1) {
        continue;
      }

      // Get the value of the bit at the given 'index' in a byte.
      const oneByte = parseInt(bitmap[2 + byteNumber * 2] + bitmap[3 + byteNumber * 2], 16);
      if ((oneByte & (1 << bitNumber)) > 0) {
        const { signature, messagePoint } = mcl.sign(message, validatorSecretKeys[i], ethers.utils.arrayify(DOMAIN));
        signatures.push(signature);
        aggVotingPower += parseInt(validatorSet[i].votingPower, 10);
      } else {
        continue;
      }
    }

    const aggMessagePoint: mcl.MessagePoint = mcl.g1ToHex(mcl.aggregateRaw(signatures));

    if (aggVotingPower > (Number(await checkpointManager.totalVotingPower()) * 2) / 3) {
      await checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray);

      expect(await checkpointManager.getEventRootByBlock(checkpoint.blockNumber)).to.equal(checkpoint.eventRoot);
      expect(await checkpointManager.checkpointBlockNumbers(1)).to.equal(checkpoint.blockNumber);
      expect(await checkpointManager.getCheckpointBlock(checkpoint.blockNumber)).to.deep.equal([
        true,
        checkpoint.blockNumber,
      ]);
      expect(await checkpointManager.getCheckpointBlock(checkpoint.blockNumber + 1)).to.deep.equal([false, 0]);

      await checkpointManager.getEventMembershipByBlockNumber(
        checkpoint.blockNumber,
        checkpoint.eventRoot,
        leafIndex,
        tree.getHexProof(leaves[leafIndex])
      );
      await checkpointManager.getEventMembershipByEpoch(checkpoint.epoch, checkpoint.eventRoot, leafIndex, tree.getHexProof(leaves[leafIndex]));
    } else {
      await expect(
        checkpointManager.submit(checkpointMetadata, checkpoint, aggMessagePoint, validatorSet, bitmap, feedInputsArray)
      ).to.be.revertedWith("INSUFFICIENT_VOTING_POWER");
    }
  });

  it("Get Event Membership By BlockNumber with invalid eventRoot", async () => {
    const blockNumber = 4;
    const leaf = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const leafIndex = 0;
    let proof = [];
    proof.push(ethers.utils.hexlify(ethers.utils.randomBytes(32)));

    await expect(
      checkpointManager.getEventMembershipByBlockNumber(blockNumber, leaf, leafIndex, proof)
    ).to.be.revertedWith("NO_EVENT_ROOT_FOR_BLOCK_NUMBER");
  });

  it("Get Event Membership By epoch with invalid eventRoot", async () => {
    const epoch = 3;
    const leaf = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const leafIndex = 0;
    let proof = [];
    proof.push(ethers.utils.hexlify(ethers.utils.randomBytes(32)));

    await expect(checkpointManager.getEventMembershipByEpoch(epoch, leaf, leafIndex, proof)).to.be.revertedWith(
      "NO_EVENT_ROOT_FOR_EPOCH"
    );
  });


  it("getPrice returns correct price for given pairIndex", async () => {
    const pairIndex = 1;  // You can change this as per your requirements
    
    const expectedPrice = ethers.utils.parseEther("1000");  // Adjust this value according to your logic

    const [returnedPrice, flag]  = await checkpointManager.getPrice(pairIndex);

    expect(returnedPrice).to.equal(expectedPrice);
    expect(flag).to.be.true; // If you also want to check the flag value
  });


  it("getPrice returns price for not existing pairIndex", async () => {
    const pairIndex = 4;  // You can change this as per your requirements
    
    const expectedPrice = ethers.utils.parseEther("0");  // Adjust this value according to your logic

    const [returnedPrice, flag]  = await checkpointManager.getPrice(pairIndex);

    expect(returnedPrice).to.equal(expectedPrice);
    expect(flag).to.be.false; // If you also want to check the flag value
  });

  it("getPrices returns correct prices and validity for given indices", async () => {
    const pairIndices = [1, 2, 3];
    
    const expectedPrices = [
        ethers.utils.parseEther("1000"), // Adjust these values according to your logic
        ethers.utils.parseEther("2000"), 
        ethers.utils.parseEther("0")
    ];

    const expectedValidity = [true, true, false];  // Adjust these values according to your logic

    const [returnedPrices, returnedValidity] = await checkpointManager.getPrices(pairIndices);

    // Check if the lengths are the same
    expect(returnedPrices.length).to.equal(expectedPrices.length);
    expect(returnedValidity.length).to.equal(expectedValidity.length);

    // Compare each price in the returned array with the expected array
    for (let i = 0; i < returnedPrices.length; i++) {
        expect(returnedPrices[i].toString()).to.equal(expectedPrices[i].toString());
        expect(returnedValidity[i]).to.equal(expectedValidity[i]);
    }
  });


});


