pragma solidity ^0.4.17;

contract BatchNoOverflow {

	mapping(address => uint256) balances;

	function batchTransferOriginal(address[] _receivers, uint256 _value) public returns (uint256) {
		uint cnt = _receivers.length;
		uint256 amount = uint256(cnt) * _value;
		
		require(cnt > 0 && cnt <= 20);
		require(_value > 0 && balances[msg.sender] >= amount);
		require(amount >= _value);

		balances[msg.sender] = balances[msg.sender] - amount;

		for (uint i = 0; i < cnt; i++) {
			balances[_receivers[i]] = balances[_receivers[i]] + _value;
		}

		return amount;
	}

	function getBalance(address _account) external view returns (uint256) {
		return balances[_account];
	}

	function getHalfUint256() external pure returns (uint256) {
		return (2**256)/2;
	}

}
