import { ethers } from "hardhat";
import type { AddressLike } from "ethers";
import { cleanWrapperDeployment, withWrappedTokens } from "./tools/fixtures";
import { getPublicKey } from "./tools/cryptography";
import "chai/register-should";
import { balanceOf, feedAccounts } from "./tools/helpers";
import { ConfidentialWrapper, TestERC20 } from "../typechain-types";

describe("ConfidentialWrapper", () => {
    const expectWrapperInvariant = async (
        token: ConfidentialWrapper,
        underlyingToken: TestERC20,
        requestedMintHolders: AddressLike[] = []
    ) => {
        let requestedMints = 0n;
        for (const holder of requestedMintHolders) {
            requestedMints += await token.requestedMints(holder);
        }
        (await underlyingToken.balanceOf(token)).should.be.equal(
            await token.totalSupply() + requestedMints
        );
    };

    it("should be able to wrap and unwrap tokens", async () => {
        const { underlyingToken, token, owner, bite } = await cleanWrapperDeployment();
        await owner.sendTransaction({
            to: await ethers.resolveAddress(token),
            value: ethers.parseEther("1.0")
        });
        await token.connect(owner).setViewerPublicKey(await getPublicKey(owner));
        await bite.sendCallback();

        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");

        const amount = ethers.parseEther("1");
        await underlyingToken.mint(owner, amount);
        await underlyingToken.approve(
            token,
            amount
        );
        await token.depositFor(owner, amount);
        await bite.sendCallback();

        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");
        (await underlyingToken.balanceOf(owner)).should.be.equal(0);
        (await underlyingToken.balanceOf(token)).should.be.equal(amount);

        await token.withdrawTo(owner, amount);
        await bite.sendCallback();
        // balance should be encrypted
        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");

        (await balanceOf(token, bite, owner)).should.be.equal(0);
        (await underlyingToken.balanceOf(owner)).should.be.equal(amount);
        (await underlyingToken.balanceOf(token)).should.be.equal(0);
    });

    it("withdrawTo(account, value) sends underlying to `account`", async () => {
        const { token, underlyingToken, owner, bite } = await cleanWrapperDeployment();
        const [, recipient] = await ethers.getSigners();
        await feedAccounts([owner, recipient]);

        await owner.sendTransaction({
            to: await ethers.resolveAddress(token),
            value: ethers.parseEther("1.0")
        });

        await token.connect(owner).setViewerPublicKey(await getPublicKey(owner));
        await bite.sendCallback();

        const amount = ethers.parseEther("1");
        await underlyingToken.mint(owner, amount);
        await underlyingToken.connect(owner).approve(token, amount);
        await token.connect(owner).depositFor(owner, amount);
        await bite.sendCallback();

        (await underlyingToken.balanceOf(owner)).should.be.equal(0);
        (await underlyingToken.balanceOf(token)).should.be.equal(amount);
        (await underlyingToken.balanceOf(recipient)).should.be.equal(0);

        // Per OZ ERC20Wrapper interface, withdrawTo(account, amount) should
        // burn from msg.sender and send `amount` of underlying to `account`.
        await token.connect(owner).withdrawTo(recipient, amount);
        await bite.sendCallback();

        // Expected safe behavior:
        // underlying should be delivered to the supplied recipient.
        (await underlyingToken.balanceOf(recipient)).should.be.equal(amount);
        (await underlyingToken.balanceOf(owner)).should.be.equal(0);
        (await underlyingToken.balanceOf(token)).should.be.equal(0);
    });

    it("should not allow two pending withdrawals from the same holder", async () => {
        const { token, owner, wrapped } = await withWrappedTokens();
        const amount = wrapped / 2n;

        await token.withdrawTo(owner, amount);
        const pending = await token.pendingBurns(owner);
        pending.recipient.should.be.equal(await ethers.resolveAddress(owner));
        pending.value.should.be.equal(amount);

        await token.withdrawTo(owner, amount)
            .should.be.revertedWithCustomError(
                token, "WithdrawalPending"
            ).withArgs(owner);
    });

    it("should allow cancelling a pending withdrawal before it finalizes", async () => {
        const { token, owner, wrapped } = await withWrappedTokens();
        const amount = wrapped / 2n;

        await token.withdrawTo(owner, amount);
        await token.cancelWithdrawTo();

        const cancelled = await token.pendingBurns(owner);
        cancelled.recipient.should.be.equal(ethers.ZeroAddress);
        cancelled.value.should.be.equal(0);

        await token.withdrawTo(owner, amount);
        const pending = await token.pendingBurns(owner);
        pending.recipient.should.be.equal(await ethers.resolveAddress(owner));
        pending.value.should.be.equal(amount);
    });

    it("should not allow cancelling when there is no pending withdrawal", async () => {
        const { token, owner } = await withWrappedTokens();

        await token.cancelWithdrawTo()
            .should.be.revertedWithCustomError(
                token, "NoPendingWithdrawal"
            ).withArgs(owner);
    });

    it("should roll back a cancelled withdrawal if its callback arrives later", async () => {
        const { token, underlyingToken, owner, bite, wrapped } = await withWrappedTokens();
        const [, recipient] = await ethers.getSigners();
        const amount = wrapped / 2n;

        await token.connect(owner).setViewerPublicKey(await getPublicKey(owner));
        await bite.sendCallback();

        const balanceBefore = await balanceOf(token, bite, owner);

        await token.withdrawTo(recipient, amount);
        await token.cancelWithdrawTo();

        await bite.sendCallback()
            .should.be.revertedWithCustomError(
                token, "OutdatedBurn"
            ).withArgs(owner, amount);

        (await balanceOf(token, bite, owner)).should.be.equal(balanceBefore);
        (await underlyingToken.balanceOf(owner)).should.be.equal(0);
        (await underlyingToken.balanceOf(recipient)).should.be.equal(0);
        (await underlyingToken.balanceOf(token)).should.be.equal(wrapped);
    });

    it("should preserve wrapper accounting while a withdrawal is pending and after it finalizes", async () => {
        const { token, underlyingToken, owner, bite, wrapped } = await withWrappedTokens();
        const [, recipient] = await ethers.getSigners();
        const amount = wrapped / 2n;

        await expectWrapperInvariant(token, underlyingToken, [owner]);

        await token.withdrawTo(recipient, amount);
        const pending = await token.pendingBurns(owner);
        pending.recipient.should.be.equal(await ethers.resolveAddress(recipient));
        pending.value.should.be.equal(amount);

        await expectWrapperInvariant(token, underlyingToken, [owner]);

        await bite.sendCallback();
        const cleared = await token.pendingBurns(owner);
        cleared.recipient.should.be.equal(ethers.ZeroAddress);
        cleared.value.should.be.equal(0);

        await expectWrapperInvariant(token, underlyingToken, [owner]);
        (await underlyingToken.balanceOf(recipient)).should.be.equal(amount);
    });

    it("should be possible to unlock underlying tokens if bite transaction fails", async () => {
        const { underlyingToken, token, owner, bite } = await cleanWrapperDeployment();
        await token.connect(owner).setViewerPublicKey(await getPublicKey(owner) , {value: ethers.parseEther("1.0")});
        await bite.sendCallback();

        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");

        const amount = ethers.parseEther("1");
        await underlyingToken.mint(owner, amount);
        await underlyingToken.approve(
            token,
            amount
        );
        await token.depositFor(owner, amount);

        // Balance hidden on registration
        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");
        (await underlyingToken.balanceOf(owner)).should.be.equal(0);
        (await underlyingToken.balanceOf(token)).should.be.equal(amount);

        await token.releaseTo(owner, amount);

        // Balance hidden on registration
        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");
        (await underlyingToken.balanceOf(owner)).should.be.equal(amount);
        (await underlyingToken.balanceOf(token)).should.be.equal(0);

        // Check if bite transaction comes later there is no "double spending"
        // and no tokens are minted.
        await bite.sendCallback()
            .should.be.revertedWithCustomError(
                token, "OutdatedMint"
            ).withArgs(owner, amount);

        (await token.encryptedBalanceOf(owner)).should.not.be.equal("0x");
        (await underlyingToken.balanceOf(owner)).should.be.equal(amount);
        (await underlyingToken.balanceOf(token)).should.be.equal(0);
    });

    it("should not allow to withdraw to the token itself", async () => {
        const { token, wrapped } = await withWrappedTokens();

        await token.withdrawTo(token, wrapped)
            .should.be.revertedWithCustomError(
                token, "ERC20InvalidReceiver"
            ).withArgs(await ethers.resolveAddress(token));
    });

    it("should return decimals of the underlying token", async () => {
        const { token, underlyingToken } = await cleanWrapperDeployment();
        (await token.decimals()).should.be.equal(await underlyingToken.decimals());
    });

    it("should return total supply", async () => {
        const { token, wrapped } = await withWrappedTokens();
        (await token.totalSupply()).should.be.equal(wrapped);
    });

    it("balanceOf should have confidential behavior", async () => {
        const { owner, token } = await withWrappedTokens();
        await token.balanceOf(owner)
            .should.be.revertedWithCustomError(token, "ValueIsEncrypted");
    });
});
