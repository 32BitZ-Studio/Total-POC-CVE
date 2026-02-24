package fr.acinq.eclair.checkfunding

import akka.util.Timeout
import fr.acinq.bitcoin.{Block, ByteVector32}
import fr.acinq.eclair.{BitcoinRPCConnectionException, BitcoinWalletDisabledException, isPay2PubkeyHash}
import fr.acinq.eclair.blockchain.bitcoind.rpc.BitcoinJsonRPCClient
import org.json4s.JsonAST.JArray

import scala.concurrent.{Await, ExecutionContext, TimeoutException}
import scala.concurrent.duration._


object CheckBitcoind {

  def check(bitcoinClient: BitcoinJsonRPCClient) = try {
    implicit val ec = ExecutionContext.Implicits.global
    implicit val timeout = Timeout(30 seconds)
    implicit val formats = org.json4s.DefaultFormats
    val future = for {
      json <- bitcoinClient.invoke("getblockchaininfo").recover { case _ => throw BitcoinRPCConnectionException }
      // Make sure wallet support is enabled in bitcoind.
      _ <- bitcoinClient.invoke("getbalance").recover { case _ => throw BitcoinWalletDisabledException }
      progress = (json \ "verificationprogress").extract[Double]
      ibd = (json \ "initialblockdownload").extract[Boolean]
      blocks = (json \ "blocks").extract[Long]
      headers = (json \ "headers").extract[Long]
      chainHash <- bitcoinClient.invoke("getblockhash", 0).map(_.extract[String]).map(s => ByteVector32.fromValidHex(s)).map(_.reverse)
      bitcoinVersion <- bitcoinClient.invoke("getnetworkinfo").map(json => (json \ "version")).map(_.extract[Int])
      unspentAddresses <- bitcoinClient.invoke("listunspent").collect { case JArray(values) =>
        values
          .filter(value => (value \ "spendable").extract[Boolean])
          .map(value => (value \ "address").extract[String])
      }
    } yield (progress, ibd, chainHash, bitcoinVersion, unspentAddresses, blocks, headers)
    // blocking sanity checks
    val (progress, initialBlockDownload, chainHash, bitcoinVersion, unspentAddresses, blocks, headers) = Await.result(future, 30 seconds)
    assert(bitcoinVersion >= 170000, "Eclair requires Bitcoin Core 0.17.0 or higher")
    assert(chainHash == Block.LivenetGenesisBlock.hash, "This tool only works on mainnet")
    if (chainHash != Block.RegtestGenesisBlock.hash) {
      assert(unspentAddresses.forall(address => !isPay2PubkeyHash(address)), "Make sure that all your UTXOS are segwit UTXOS and not p2pkh (check out our README for more details)")
    }
    assert(!initialBlockDownload, s"bitcoind should be synchronized (initialblockdownload=$initialBlockDownload)")
    assert(progress > 0.999, s"bitcoind should be synchronized (progress=$progress)")
    assert(headers - blocks <= 1, s"bitcoind should be synchronized (headers=$headers blocks=$blocks)")
  } catch {
    case e: IllegalArgumentException => println(e.getMessage); System.exit(1)
    case BitcoinRPCConnectionException => println("could not connect to bitcoind using json-rpc"); System.exit(1)
    case _: TimeoutException => println(s"bitcoind timed out"); System.exit(1)
  }

}
