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

import scopt.OParser

object Boot extends App {

  val builder = OParser.builder[Conf]
  val parser = {
    import builder._
    OParser.sequence(
      programName("checkfunding"),
      head("checkfunding", "1.0"),
      opt[File]("db")
        .required()
        .valueName("<eclair.sqlite>")
        .action((db, conf) => conf.copy(eclairDb = db))
        .text("path to eclair.sqlite"),
      opt[File]("conf")
        .optional()
        .valueName("<eclair.conf>")
        .action((c, conf) => conf.copy(eclairConf = c))
        .text("path to eclair.conf"),
      help("help").text("prints this usage text"),
      note(
        """
          |This utility will detect if your node has been victim of CVE-2019-13000.
          |Please see the thread on https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-August/002130.html for more details on the vulnerability.
          |
          |NB: This tool will only work if you have been using released versions of Eclair. If you are on e.g. latest master, please contact support.
          |
          |Example: checkfunding --db /path/to/eclair.sqlite --conf /path/to/eclair.conf
          |""".stripMargin))
  }

  OParser.parse(parser, args, Conf()) match {
    case Some(conf) =>
      CheckFunding.check(conf)
    case _ =>
      // arguments are bad, error message will have been displayed
      System.exit(1)
  }

}
