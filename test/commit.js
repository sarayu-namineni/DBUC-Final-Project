/**
 * @file commit.js
 * @brief Helper functions for generating and formatting commitments
 * 
 * @author Sarayu Namineni (snaminen)
 */
const crypto = require("crypto");

/** 
 * @brief Formats commitment for ZKP circuit
 * 
 * Convert a hex string (no 0x prefix) into an array of numParts 32-byte hex strings 
 * in big-endian order to be used as input/output for SHA256Packed
 * 
 * @param hexString String of hex values
 * @param numParts Number of parts to split string into
 * 
 * @returns Array of partial hex strings
 */
function hexStrToSHA256Packed(hexString, numParts){
	let inputArr = [];

	let remainder = hexString.length % 32;
	if (remainder) {
		inputArr[0] = "0x" + hexString.substring(0, remainder);
		hexString = hexString.substring(remainder);
	}

	let matchArr = hexString.match(/.{1,32}/g);
	if (matchArr) {
		matchArr.map(matchElem => "0x" + matchElem);
		inputArr = inputArr.concat(matchArr);
	}

	let fillArr = Array(numParts - inputArr.length).fill("0");
	if (fillArr) {
		inputArr = fillArr.concat(inputArr);
	}

	return inputArr;
}

/**
 * @brief Formats preimage to commitment for ZKP circuit
 * 
 * @param {*} str Preimage
 * @returns SHA-256 hash
 */
function commitStr(str) {
	let paddedStr = str.padStart(128, "0");
	let paddedHexStr = Buffer.from(paddedStr, "hex");
			
	const hash = crypto.createHash('sha256').update(paddedHexStr).digest("hex");

	return hash;
}

/**
 * @brief Generates participant's commitment when joining poll
 * 
 * @returns Participant's public passphrase and private passphrase (needed to cast a vote)
 * and commitment of passphrases (needed to join for the poll)
 */
function getVoteCommitment(){
	let pubStr = crypto.randomBytes(16).toString("hex");
	let privStr = crypto.randomBytes(16).toString("hex");
	let str = pubStr.concat(privStr);
	const commitmentStr = commitStr(str);
	let newCommitmentStr = hexStrToSHA256Packed(commitmentStr, 2);
	let newCommitment = newCommitmentStr.map(commit => BigInt("0x" + commit));
	return [pubStr, privStr, newCommitment];
}

module.exports = {
	hexStrToSHA256Packed,
	commitStr,
	getVoteCommitment
}