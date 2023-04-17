// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Verifier} from "./Verifier.sol";

struct PollForm {
	string pollQuestion;
	string[] pollChoices;
}

// Collects distinct, anonymous responses to a multiple choice poll
// Can have a maximum of 50 participants
contract Poll {
	// ZKP state
	Verifier verifier;

	// Organizer state
	address organizer;
	PollForm pollForm;
	mapping (string => bool) isPollChoice;
	mapping (string => uint32) tally;

	// Participant state
	string[] participants;
	uint[] commitments;
	string[] passphrases;

	// Voting mechanism state (ensures that each vote comes from a distinct participant)
	mapping (string => bool) participantExists;
	mapping (bytes32 => bool) commitmentExists;
	mapping (string => bool) passphraseExists;

	// Initializes contract with a poll question and poll choices
	// Initializes contract with a verifier that checks the validity of a vote
	constructor(address _verifierAddress, string memory _pollQuestion, string[] memory _pollChoices) {
		verifier = Verifier(_verifierAddress);
		organizer = msg.sender;
		pollForm.pollQuestion = _pollQuestion;
		pollForm.pollChoices = _pollChoices;
		for (uint32 i = 0; i < _pollChoices.length; i++){
			isPollChoice[pollForm.pollChoices[i]] = true;
		}
	}

	// A participant registers to join the poll by publishing a commitment of two random hex strings, 
	// which correspond to a public and private passphrase
	function joinPoll(string calldata participant, uint[2] calldata newCommitment) public {
		require(participants.length < 50, "Too many participants");
		bytes32 commitHash = keccak256(abi.encodePacked(newCommitment[0], newCommitment[1]));
		if (!(participantExists[participant] || commitmentExists[commitHash])) {
			participants.push(participant);
			participantExists[participant] = true;

			commitments.push(newCommitment[0]);
			commitments.push(newCommitment[1]);
			commitmentExists[commitHash] = true;
		}
	}

	// A participant votes by revealing their public passphrase and a proof that they know the private
	// passphrase needed to generate one of the commitments that were registered earlier
	function vote(string calldata pollVote, string calldata passphrase, Verifier.Proof memory proof, uint[102] memory inputs) public {
		require(isPollChoice[pollVote], "Not a valid poll choice");
		for (uint i = 0; i < 2; i+=2){
			bytes32 commitHash = keccak256(abi.encodePacked(inputs[i], inputs[i+1]));
			require(commitmentExists[commitHash], "Commitment does not exist");
		}
		require(verifier.verifyTx(proof, inputs), "Proof did not verify");
		require(!passphraseExists[passphrase], "Passphrase seen before");
		tally[pollVote]++;
	}

	// Returns the poll question and choices
	function getPoll() public view returns (PollForm memory) {
		return pollForm;
	}

	// Returns a list of the participants that have joined
	function getParticipants() public view returns (string[] memory) {
		return participants;
	}

	// Returns a list of the commitments participants have published
	function getCommitments() public view returns (uint[] memory) {
		return commitments;
	}

	// Returns the total number of votes for the given poll choice
	function getPollResult(string calldata pollChoice) public view returns (uint32) {
		require(msg.sender == organizer, "You are not the organizer");
		require(isPollChoice[pollChoice]);
		return tally[pollChoice];
	}
	
}