/** 
 *  @file prove.js
 *  @brief Helper functions for generating zero-knowledge proofs
 *  
 *  @author Sarayu Namineni (snaminen)
 */
const fs = require("fs");
const { hexStrToSHA256Packed } = require("./commit.js");

const MAXLEN = 100;
const PREIMAGE = 4;

/**
 * @brief Generates a proof for the specified program using the specified proving key and arguments
 * 
 * @param {*} programPath Circuit 
 * @param {*} pkPath Proving key
 * @param {*} args Public and private inputs to circuit
 * 
 * @returns ZKP for given circuit
 */
async function prove(programPath, pkPath, args){
	let { initialize } = await import("zokrates-js");
	return initialize().then((zokratesProvider) => {
		// get program artifacts
		const source = (fs.readFileSync(programPath)).toString();
		const artifacts = zokratesProvider.compile(source);
		const pk = fs.readFileSync(pkPath);

		// compute witness
		const { witness, output } = zokratesProvider.computeWitness(artifacts, args);

		// generate proof
		const proof = zokratesProvider.generateProof(artifacts.program, witness, pk);

		return proof;
	})
}

/**
 * @brief Generates a proof that the participant previously joined the poll
 * 
 * @param {*} commitments List of participant commitments from when they joined
 * @param {*} index Index of the current participant's commitment
 * @param {*} pubStr Public parameter to current participant's commmitment
 * @param {*} privStr Private parameter to current participant's commitment
 * 
 * @returns ZKP for voting circuit
 */
async function proveVoteCommitment(commitments, index, pubStr, privStr){
	assert(commitments.length <= MAXLEN && commitments.length % 2 == 0);
	const voteProgram = "./vote.zok";
	const votePK = "./vote-proving.key";

	let fillArr = Array(MAXLEN - commitments.length).fill("0");
	if (fillArr) {
		commitments = commitments.concat(fillArr);
	}
	let pubStrArr = hexStrToSHA256Packed(pubStr, PREIMAGE);
	let privStrArr = hexStrToSHA256Packed(privStr, PREIMAGE);
	let args = [commitments, commitments.length.toString(), index.toString(), pubStrArr[3], privStrArr[3]];

	return prove(voteProgram, votePK, args);
}

module.exports = {
	proveVoteCommitment
}