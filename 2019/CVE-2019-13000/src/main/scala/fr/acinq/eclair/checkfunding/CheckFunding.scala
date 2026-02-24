/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.checkfunding

import java.io.File
import java.nio.file.Files
import java.sql.DriverManager

import akka.util.Timeout
import com.softwaremill.sttp.okhttp.OkHttpFutureBackend
import com.typesafe.config.ConfigFactory
import fr.acinq.bitcoin.{ScriptFlags, Transaction}
import fr.acinq.eclair.blockchain.bitcoind.rpc.{BasicBitcoinJsonRPCClient, ExtendedBitcoinClient}
import fr.acinq.eclair.db.sqlite.SqliteChannelsDb

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext}
import scala.util.{Failure, Success, Try}

object CheckFunding extends App {

  def check(conf: Conf) = {
    implicit val sttpBackend = OkHttpFutureBackend()
    implicit val timeout = Timeout(30 seconds)
    implicit val formats = org.json4s.DefaultFormats
    implicit val ec = ExecutionContext.Implicits.global

    try {

      val channelsDbTmp = new File("eclair.sqlite.detectiontool.tmp")
      channelsDbTmp.delete()
      channelsDbTmp.deleteOnExit()
      Files.copy(conf.eclairDb.toPath, channelsDbTmp.toPath)

      val sqlite = DriverManager.getConnection(s"jdbc:sqlite:$channelsDbTmp")
      val channelsDb = new SqliteChannelsDb(sqlite)

      val config = ConfigFactory.parseProperties(System.getProperties)
        .withFallback(ConfigFactory.parseFile(conf.eclairConf))
        .withFallback(ConfigFactory.load()).getConfig("eclair")


      val bitcoinClient = new ExtendedBitcoinClient(new BasicBitcoinJsonRPCClient(
        user = config.getString("bitcoind.rpcuser"),
        password = config.getString("bitcoind.rpcpassword"),
        host = config.getString("bitcoind.host"),
        port = config.getInt("bitcoind.rpcport")))

      CheckBitcoind.check(bitcoinClient.rpcClient)

      val channels = channelsDb.listLocalChannels()

      println(s"checking ${channelsDb.listLocalChannels().size} channel(s)")

      val errors = channels
        .foldLeft(0) { (errors, channel) =>
          val fundingTxid = channel.commitments.commitInput.outPoint.txid.toString()
          Try(Await.result(bitcoinClient.getTransaction(fundingTxid), 30 seconds)) match {
            case Success(fundingTx) =>
              Try(Transaction.correctlySpends(channel.commitments.localCommit.publishableTxs.commitTx.tx, Seq(fundingTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)) match {
                case Success(_) =>
                  println(s"channelId=${channel.channelId} : ok")
                  errors
                case Failure(_) =>
                  println(s"channelId=${channel.channelId} : invalid funding!!")
                  errors + 1
              }
            case Failure(_) =>
              println(s"channelId=${channel.channelId} : ok (funding tx not found)")
              // funding tx hasn't yet been published, that's ok
              errors
          }
        }

      if (errors == 0) {
        println("result: OK, no exploit detected")
      } else {
        println(s"result: *found $errors invalid funding tx(es)* please contact support")
      }

      sqlite.close()

    } finally {
      sttpBackend.close()
    }
  }

}
