/** 
 * @file index.js
 * @brief Tests for Poll contract
 * 
 * @author Sarayu Namineni (snaminen)
 */
const Poll = artifacts.require("Poll");
const Verifier = artifacts.require("Verifier");
const { getVoteCommitment } = require("./commit");
const { proveVoteCommitment } = require("./prove");

contract('Poll', (accounts) => {
	it('single join and vote', async () => {
	  // Organizer initializes poll with question and choices
	  const organizer = accounts[0];
	  const pollQuestion = "What is your favorite color?";
	  const pollChoices = ["Red", "Blue", "Green"];
	  const verifierContract = await Verifier.deployed();
	  const pollInstance = await Poll.new(verifierContract.address, pollQuestion, pollChoices, { from: organizer });

	  // Participant janedoe joins the poll
	  const participant = "janedoe";
	  const [pubStr, privStr, newCommitment] = getVoteCommitment();
      
	  await pollInstance.joinPoll(participant, newCommitment, { from: accounts[1] });

	  // Participant janedoe votes for her favorite color "Red" in the poll
	  const voteA = "Red";
	  const commitments = await pollInstance.getCommitments();
	  const proof = await proveVoteCommitment(commitments, 0, pubStr, privStr);

	  await pollInstance.vote(voteA, pubStr, proof.proof, proof.inputs, { from: accounts[1] });

	  // Tally up the votes from the poll
	  const pollChoiceOneVotes = await pollInstance.getPollResult(pollChoices[0], { from: organizer });
	  const pollChoiceTwoVotes = await pollInstance.getPollResult(pollChoices[1], { from: organizer });
	  const pollChoiceThreeVotes = await pollInstance.getPollResult(pollChoices[2], { from: organizer });

	  // Assert that "Red" has one vote from janedoe
	  assert(pollChoiceOneVotes == 1);
	  assert(pollChoiceTwoVotes == 0);
	  assert(pollChoiceThreeVotes == 0);
	});
});