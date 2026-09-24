// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./MockERC20.sol";

/// @notice Mock router with Uniswap SwapRouter02's exactInputSingle ABI. Fixed rate.
contract MockSwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    /// @dev amountOut = amountIn * rateNum / rateDen. Updated by the keeper from the market price (testnet).
    uint256 public rateNum;
    uint256 public rateDen;
    address public immutable keeper;

    event RateUpdated(uint256 rateNum, uint256 rateDen);

    constructor(uint256 rateNum_, uint256 rateDen_) {
        rateNum = rateNum_;
        rateDen = rateDen_;
        keeper = msg.sender;
    }

    function setRate(uint256 rateNum_, uint256 rateDen_) external {
        require(msg.sender == keeper, "keeper only");
        require(rateNum_ != 0 && rateDen_ != 0, "zero rate");
        rateNum = rateNum_;
        rateDen = rateDen_;
        emit RateUpdated(rateNum_, rateDen_);
    }

    function exactInputSingle(ExactInputSingleParams calldata p) external payable returns (uint256 amountOut) {
        IERC20(p.tokenIn).transferFrom(msg.sender, address(this), p.amountIn);
        amountOut = p.amountIn * rateNum / rateDen;
        require(amountOut >= p.amountOutMinimum, "slippage");
        MockERC20(p.tokenOut).mint(p.recipient, amountOut);
    }
}
