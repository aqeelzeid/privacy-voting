## **Problem / Challenge Statement**

Our current voting system is **not privacy-preserving**: it reveals individual votes. 
Trust is maintained between the platform and users but **not among the users themselves**, 
which limits the security and autonomy of the voting process.
## Goal

1. The goal  is to **create a secure, decentralized voting system for a committee of voters** where:
	1. Only eligible voters can cast a ballot, and each voter can vote only once.
	2. Votes are kept **confidential**, so no one — including the platform or other voters — can link a vote to a voter.
	3. Votes can be **aggregated and tallied** to compute results without revealing individual ballots.
	4. Trust and critical operations are **distributed among the voters themselves**, eliminating the need for a central authority.

2.  Integrate the new voting system to our platform so it meshes with the existing systems and flows.

Todo 
1.  Research Existing Solutions: Understand the tools and technologies available. 
	1. Grasp of the problem space and solutions ✅
	2. Distributed Key Generation : Understand Secret Sharing and Verifiable Secret Sharing Processes ✅
	3. Threshold Signing:  Understand Threshold Signing Process. ✅
	4. Understanding Blind Signatures. ✅
	5. Understand Homomorphic Encryption and Tallying. ✅
	6. Look into what libraries are available for implementation. ✅
2.  Proof Of Concept:  ✅
	1. Create a separate repo for Privacy Preserving Voting Proof Of Concept ✅ 
		1. Typescript repo setup ✅
		2. Testing Harness. ✅
	2. Bring in needed primitives (types, ports, adapters) form existing project to ensure smooth integration to the main project. ✅
	3. Create End 2 End DKG Process.
		1. Distributed Key Generation Flow
			1. Design the types for DKG.
			2. Design the ports for DKG.
			3. Implement the BLS Adapter for Distributed Key Generation Port
			4. Unit Test BLS Adapter
		2.  Distributed Threshold Signature Flow
			1.  Design and Implement the type for threshold signature flow.
			2.  Design and Implement port for threshold signature flow
			3. Design and Implement BLS adapter for threshold signature flow.
			4. Unit Test BLS Threshold Signature Flow
	  4. Create End 2 End Blind Signature Process.
		  1. Design the End 2 End Blind Signature Process (types, flows etc.)
		  2. Implement the port for blind signature process.
		  3. Implement the adapter for blind signature process.
		  4. Unit Test End 2 End Blind Signature process.
	5. Create End 2 End Homomorphic encryption module. 
		1. Distributed Key Generation Flow For Homomorphic Encryption
			1. Implement the Pallier Adapter for Distributed Key Generation Port.
			2. Unit Test Pallier DKG Adapter
		2. Create Homomorphic Voting Adapter
			1. Design the homomorphic voting port , types, and flow.
			2. Implement the Pallier Homomorphic Voting Adapter.
			3. Unit Test Pallier Homomorphic Voting Adapter
	6. Create Privacy Preserving Voting Process Interface
		1. Full end 2 end voting process
			1. Ballot generation and approval.
			2. Casting.
			3. Tallying.
		2.  Unit Test Privacy Preserving Voting Process 
	7. Integrate All pieces to create a full voting Flow.
		1. Committee Creation 
			1. Threshold Signature DKG Flow.
			2. Threshold Homomorphic Encryption DKG Flow. 
		2.  Voting Process
			1. Open/Initialize Vote.
			2. Ballot generation and approval
			3. Vote Casting 
			4. Vote Evaluation (Tallying)
3.  Impact analysis on current system , integration and refactoring plan. 
4. Integration & Refactor.
	1. Remove Voting and Proposal UIs From Individual Sections and Create a separate voting page.  Noora 
	2. Implement Proposal Micro frontend
		1. Proposal Micro Frontend Component (Pass in the proposal Id, and or type and render the Relevant Proposal UI in its correct state.)
		2. Make proposal creation UIs and embed them in relevant sections as pop ups.
			1. Update Profile
			2. Add Member
			3. Create Committee
				1. Create Open Voting Committee.
				2. Create Privacy Preserving Voting Committee.
			4. Change authority
				1. Change Privacy
					1. Make Private to Public
					2. Make Public to Private
		3. Implement Proposal UIs
			1. Update Profile
			2. Add Member
			3. Create Committee
				1. Create Open Voting Committee.
				2. Create Privacy Preserving Voting Committee.
			4. Change authority
				1. Change Privacy
					1. Make Private to Public
					2. Make Public to Private
	3.  Implement Voting Section.
		1. Show all proposals and help user find and select and preview them.
		2. Ui to create a voting session from a selected proposal.
		3. Show list of active votes and let the user view the voting micro frontend of an active vote.
	4.  Implement Voting Micro Frontend
		1. Voting Micro frontend component. (Pass in voting Id and or type and render the relevant voting session in its correct state.)
		 2. Voting Session UI For Executive Approval Voting Process
			 1. Approval Collection & Execution Page (Collects signatures from committee members)
		3.  Voting Session UI For Privacy Preserving Voting Process
			1. Vote Open Step (Define voting period, quorum, threshold, and  signature/decryption thresholds )
			2. Ballot Generation and Approval Step.
			3. Casting Step 
			4. Vote Closing & Evaluation Step
			5. Result Implementation Step.
	5. New Notifications API  
		1. New UI Components for Notification (display + link + status) simply notify user to jump to a part of the application where attention is needed.
		2. New View Model For Notifications.
		3. New API For Notifications.
	6. Refactor Proposal API (domain + backend)
		1.  Fx (state + Pre-requisite) -> final state  instead of resultant state. (at any given moment if pre-requisite fail for current state you cant pass proposal)
		2. Proposal Creation APIs 
			1. Add new member
			2. Create commitee
		3. Refactor Generic Proposal  
			1. Create 
			2. Update 
				1. Update Proposal 
				2. Update Proposal + Proposal Registry (status update.)
			3. Read.
	7. Refactor Voting API (domain + backend) 
	8. New View Model For Proposals
	9. New View Model For Voting
		1. View Model For Executive Approval Process
		2. View Mode for Privacy Preserving Process
	10. New View Simple View Model For Group Page.

Domain Model,  Backend ,  View Model (back of the frontend),  UI (front of the frontend)