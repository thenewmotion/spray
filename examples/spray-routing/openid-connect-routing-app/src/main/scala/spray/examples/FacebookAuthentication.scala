package spray.examples

import spray.client.pipelining._
import spray.json._
import spray.http._
import spray.http.Uri.Query
import spray.httpx.SprayJsonSupport
import spray.routing.authentication._
import spray.util._
import javax.net.ssl.SSLContext
import scala.concurrent.ExecutionContext
import akka.actor.ActorSystem

/**
 * Simple implementation of the Facebook OAuth authentication mechanisms.
 * NOTE: THIS IS A SAMPLE ONLY, IT DOES NOT STORE OR CACHE THE TOKENS IN ANY WAY,
 * NEITHER IS THE SECURITY STATE RANDOMIZED OR SECURE.
 * IT DOES NOT RENEW TOKENS NOR VALIDATE THE LIFECYCLE OF TOKENS
 *
 * In Order to use this sample, you need to register your application at facebook
 * and obtain a client ID and clientSecret.
 * See: https://developers.facebook.com/docs/facebook-login/login-flow-for-web-no-jssdk/ for more information
 *
 * e.g. Use this for your own good, implement proper security and storage of tokens.
 *
 * @param oauthCallbackUrl Callback URI that is used for facebook to send authorization response
 * @param system  implicit found actor system
 * @param log implicit found log system
 */
class FacebookAuthentication(oauthCallbackUrl: Uri)(implicit system: ActorSystem, log: LoggingContext) extends OAuthTransformer {

  /**
   * response by the facebook call to return an identity
   */
  case class OAuthIdentityResponse(id: String, name: String, first_name: String, last_name: String, link: String, username: String, gender: String, email: String, timezone: Int, locale: String, verified: Boolean, updated_time: String)

  object OAuthClientJsonProtocol extends DefaultJsonProtocol {
    implicit val oAuthIdentityResponseFormat = jsonFormat12(OAuthIdentityResponse)
  }

  import ExecutionContext.Implicits.global
  import OAuthClientJsonProtocol._
  import SprayJsonSupport._


  // facebook
  private val authServer = Uri("https://www.facebook.com/dialog/oauth")
  private val tokenServer = Uri("https://graph.facebook.com/oauth/access_token")
  private val clientId = "YOUR_CLIENT_ID_HERE"
  private val clientSecret = "YOUR_CLIENT_SECRET_HERE"
  private val identityUrl = "https://graph.facebook.com/me"
  //https://graph.facebook.com/me?access_token=

  private implicit val mySSLContext: SSLContext = {
    val context = SSLContext.getDefault
    context
  }

  def loginUrl =
    s"""
     |$authServer?
     |client_id=$clientId&
     |response_type=code&
     |state=AAAAAAA&
     |redirect_uri=$oauthCallbackUrl&
     |scope=email
    """.stripMargin
  //     |scope=openid%20email&


  def accessToken(code: OAuthAuthorizationCode): Option[OAuthAccessToken] = {

    val pipeline = logRequest(log) ~> sendReceive ~> logResponse(log)

    val postData = FormData(Map("code" -> code.code, "client_id" -> clientId, "client_secret" -> clientSecret,
      "redirect_uri" -> (oauthCallbackUrl.toString), "grant_type" -> "authorization_code"))

    val responseFuture = pipeline { Post(tokenServer, postData) }
    val result = responseFuture.await
    result match {
      case HttpResponse(StatusCodes.OK, entity, _, _) => {
        log.debug("OK result = " + entity.asString)
        Query(entity.asString).get("access_token").map(t => OAuthAccessToken(t)).orElse(None)
      }
      case _ => {
        log.debug("result = " + result)
        None
      }
    }
  }


  def userContext(accessToken: OAuthAccessToken): Option[OAuthIdentity] = {

    val pipeline = logRequest(log) ~> sendReceive ~> logResponse(log)

    val responseFuture = pipeline {
      addCredentials(OAuth2BearerToken(accessToken.token)) { Get(identityUrl) }
    }

    val result = responseFuture.await
    result match {
      case HttpResponse(StatusCodes.OK, entity, _, _) => {
        log.debug("OK result = " + entity.asString)
        val fbId = entity.asString.asJson.convertTo[OAuthIdentityResponse]
        Some(OAuthIdentity(fbId.id, Some(fbId.first_name), Some(fbId.last_name)))
      }
      case _ => {
        log.debug("result = " + result)
        None
      }
    }
  }

  def callBackRoute(pathName: String): _root_.spray.routing.Route = {
    import spray.routing.directives.BasicDirectives._
    import spray.routing.directives.DebuggingDirectives._
    import spray.routing.directives.PathDirectives._
    import spray.routing.directives.ParameterDirectives._
    import spray.routing.directives.RouteDirectives._
    import spray.http.MediaTypes._
    import spray.routing.directives.RespondWithDirectives._

    pathPrefix(pathName) {
      logRequest("oauthCallBack") {
        extract(_.request) {
          found =>
            log.debug("callback:" + found.toString)

            parameters('code.as[String] ?, 'state.as[String] ?, 'session_state.as[String] ?) {
              (code: Option[String], state: Option[String], sessionState: Option[String]) =>
                val accessToken = code.map(cbCode => this.accessToken(OAuthAuthorizationCode(cbCode))).orElse(None)

                accessToken match {
                  case Some(res) => {
                    log.debug("access token:" + res)
                    val userInfo = this.userContext(res.get)
                    log.debug("user Info:" + userInfo)
                    respondWithMediaType(`text/html`) {
                      complete {
                        <html>
                          <p>Bearer token: {res}</p>
                          <p>User Info: {userInfo}</p>
                        </html>
                      }
                    }
                  }
                  case _ => {
                    respondWithMediaType(`text/html`) {
                      complete {
                        <html>
                          <p>No accessToken found</p>
                        </html>
                      }
                    }
                  }
                }
            }
        }
      }
    }
  }
}
