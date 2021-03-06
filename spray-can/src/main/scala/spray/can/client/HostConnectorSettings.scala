/*
 * Copyright (C) 2011-2013 spray.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package spray.can.client

import com.typesafe.config.Config
import scala.concurrent.duration.Duration
import spray.util._

case class HostConnectorSettings(
    maxConnections: Int,
    maxRetries: Int,
    pipelining: Boolean,
    idleTimeout: Duration,
    connectionSettings: ClientConnectionSettings) {

  require(maxConnections > 0, "max-connections must be > 0")
  require(maxRetries >= 0, "max-retries must be >= 0")
  requirePositiveOrUndefined(idleTimeout)
}

object HostConnectorSettings extends SettingsCompanion[HostConnectorSettings]("spray.can.host-connector") {
  def fromSubConfig(c: Config) = apply(
    c getInt "max-connections",
    c getInt "max-retries",
    c getBoolean "pipelining",
    c getDuration "idle-timeout",
    ClientConnectionSettings fromSubConfig c.getConfig("client"))
}