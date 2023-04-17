var Verifier = artifacts.require("Verifier");
var Poll = artifacts.require("Poll");

module.exports = async function(deployer) {
	await deployer.deploy(Verifier);
	await Verifier.deployed();
	await deployer.deploy(Poll, Verifier.address, "", []);
};