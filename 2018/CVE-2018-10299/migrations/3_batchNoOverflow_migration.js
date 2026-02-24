var BatchNoOverflow = artifacts.require("./BatchNoOverflow.sol");

module.exports = function(deployer) {
  deployer.deploy(BatchNoOverflow);
};
