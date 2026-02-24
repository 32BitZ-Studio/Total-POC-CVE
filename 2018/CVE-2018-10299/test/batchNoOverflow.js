var BatchNoOverflow = artifacts.require("BatchNoOverflow");

contract('BatchNoOverflow', function (accounts) {
	
	it("account[0] should have 0 balance", function () {
		return BatchNoOverflow.deployed()
		.then(function (instance) {
			return instance.getBalance.call(accounts[0]);
		}).then(function (balance) {
			assert.equal(balance.valueOf(), 0, `account[0] was not empty, balance was ${balance.valueOf()}`);
		});
	});

	it("accounts[0] should NOT cause overflow, accounts[0] should stay 0", function () {
		let _instance;
		let _bigNumber;
		let _err;
		const accountsToTransferTo = [accounts[0], "0x000000000"];

		return BatchNoOverflow.deployed()
		.then(function (instance) {
			_instance = instance;
			return _instance.getHalfUint256.call();
		})
		.then(function (bigNum) {
			_bigNumber = bigNum;
			// Expecting this to throw an error at
			// require(balances[msg.sender] > (balances[msg.sender] - amount))
			return _instance.batchTransferOriginal(accountsToTransferTo, bigNum.valueOf(), { from:accounts[0] });
		})
		.catch(function(err) {
			_err = err.message;
			return _instance.getBalance.call(accounts[0], { from:accounts[0] });
		})
		.then(function (balance) {
			assert.equal(_err.includes("revert"), true, `Was not a revert`);
			assert.equal(0, balance.valueOf(), `accounts[0] balance incorrect`);
		})

	});

});