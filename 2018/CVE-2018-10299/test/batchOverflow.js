var BatchOverflow = artifacts.require("BatchOverflow");

contract('BatchOverflow', function (accounts) {
	
	it("account[0] should have 0 balance", function () {
		return BatchOverflow.deployed()
		.then(function (instance) {
			return instance.getBalance.call(accounts[0]);
		}).then(function (balance) {
			assert.equal(balance.valueOf(), 0, `account[0] was not empty, balance was ${balance.valueOf()}`);
		});
	});

	it("accounts[0] should cause overflow, accounts[0] has big balance now", function () {
		let _instance;
		let _bigNumber;
		const accountsToTransferTo = [accounts[0], "0x000000000"];

		return BatchOverflow.deployed()
		.then(function (instance) {
			_instance = instance;
			return _instance.getHalfUint256.call();
		})
		.then(function (bigNum) {
			_bigNumber = bigNum;
			return _instance.batchTransferOriginal(accountsToTransferTo, bigNum.valueOf(), { from:accounts[0] });
		})
		.then(function (batchTransferOriginalResult) {
			return _instance.getBalance.call(accounts[0], { from:accounts[0] });
		})
		.then(function (balance) {
			assert.equal(_bigNumber, balance.valueOf(), `accounts[0] balance incorrect`);
		});
	});

});