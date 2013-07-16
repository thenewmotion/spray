package spray.examples

import spray.client.pipelining._
import spray.http._
import spray.util._
import javax.net.ssl.SSLContext
import akka.actor.ActorSystem
import spray.routing.authentication._
import scala.concurrent.ExecutionContext
import spray.json._
import spray.httpx.SprayJsonSupport
import spray.routing.authentication.OAuthAccessToken
import spray.http.OAuth2BearerToken
import scala.Some
import spray.routing.authentication.OAuthIdentity
import spray.routing.authentication.OAuthAuthorizationCode


/**
 * Simple implementation of the Google OAuth authentication mechanisms.
 * NOTE: THIS IS A SAMPLE ONLY, IT DOES NOT STORE OR CACHE THE TOKENS IN ANY WAY,
 * NEITHER IS THE SECURITY STATE RANDOMIZED OR SECURE.
 * IT DOES NOT RENEW TOKENS NOR VALIDATE THE LIFECYCLE OF TOKENS
 *
 * In Order to use this sample, you need to register your application at google
 * and obtain a client ID and clientSecret.
 * See: https://developers.google.com/accounts/docs/OAuth2WebServer for more information
 *
 * e.g. Use this for your own good, implement proper security and storage of tokens.
 *
 * @param oauthCallbackUrl Callback URI that is used for google to send authorization response
 * @param system  implicit found actor system
 * @param log implicit found log system
 */
class GoogleAuthentication(oauthCallbackUrl: Uri)(implicit system: ActorSystem, log: LoggingContext) extends OAuthTransformer {

	// response by the google call to get an access token based on a given code.
	case class OAuthAccessTokenResponse(access_token: String, token_type: String, expires_in: Int, id_token: String)
	case class OAuthIdentityResponse(id: String, email: String, verified_email: Boolean, hd: String)

	object OAuthClientJsonProtocol extends DefaultJsonProtocol {
	  implicit val oAuthAccessTokenResponseFormat = jsonFormat4(OAuthAccessTokenResponse)
	  implicit val oAuthIdentityResponseFormat = jsonFormat4(OAuthIdentityResponse)
	}

  import ExecutionContext.Implicits.global
  import OAuthClientJsonProtocol._
  import SprayJsonSupport._


  private val authServer = Uri("https://accounts.google.com/o/oauth2/auth")
  private val tokenServer = Uri("https://accounts.google.com/o/oauth2/token")
  private val clientId = "YOUR_CLIENT_ID_HERE"
  private val clientSecret = "YOUR CLIENT SECRET HERE"
  private val identityUrl = "https://www.googleapis.com/oauth2/v1/userinfo"

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
  // additional values for google
  //     |scope=openid%20email&
  //     |login_hint=olger@spectare.nl
  //NOTE: if you add the scope, you'll get other responses and need to adapt the response case classes
  // and their json formats


  def accessToken(code: OAuthAuthorizationCode): Option[OAuthAccessToken] = {

    val pipeline = logRequest(log) ~> sendReceive ~> logResponse(log) ~> unmarshal[OAuthAccessTokenResponse]

    val postData = FormData(Map("code" -> code.code, "client_id" -> clientId, "client_secret" -> clientSecret,
      "redirect_uri" -> (oauthCallbackUrl.toString), "grant_type" -> "authorization_code"))

    val responseFuture = pipeline { Post(tokenServer, postData) }
    val result = responseFuture.await
	
    result match {
      case OAuthAccessTokenResponse(a,b,c,d) => {
        log.debug("found " + a)
        Some(OAuthAccessToken(a))
      }

      case _ => None
    }
  }


  def userContext(accessToken: OAuthAccessToken): Option[OAuthIdentity] = {

    val pipeline = logRequest(log) ~> sendReceive ~> logResponse(log) ~> unmarshal[OAuthIdentityResponse]

    val responseFuture = pipeline {
      addCredentials(OAuth2BearerToken(accessToken.token)) { Get(identityUrl) }
    }

    val result = responseFuture.await
    result match {
      case OAuthIdentityResponse(id, email, verified, hd) => {
        log.debug("success " + email)
        // convert over here an identity response to the identity case class
        Some(OAuthIdentity(email))
      }
      case _ => {
        log.debug("error " + result)
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
