package spray.examples

import scala.concurrent.duration._
import akka.actor.ActorSystem
import spray.routing.SimpleRoutingApp
import spray.http.MediaTypes._
import spray.routing.authentication.OAuth
import scala.concurrent.ExecutionContext
import spray.http._
import spray.util._

object Main extends App with SimpleRoutingApp {


  implicit val system = ActorSystem("oidc-routing-app")
  implicit val log = LoggingContext.fromActorSystem(system)

  // Configuration

  // NOTE: You need a host that is accessible for external servers
  val appHomeUrl = "http://yourhost.domain.com"
  val callbackRoute = "oauthcallback"
  val oauthCallbackUrl = Uri(appHomeUrl + "/" + callbackRoute)

  import ExecutionContext.Implicits.global

  //val oauthComm = new GoogleAuthentication(oauthCallbackUrl)
  // Try the other sample by commenting the Google one and enabling the Facebook one.
  // NOTE: Both implementations are samples only. A starting point for embedding it in your infrastructure
  val oauthComm = new FacebookAuthentication(oauthCallbackUrl)


  // use "localhost" for local binding only, as this uses a callback of an authorization server
  // you probably need to bind it to a port that's available outside this host.
  startServer("0.0.0.0", port = 8080) {
    get {
      path("") {
        redirect("/hello", StatusCodes.Found)
      } ~
      path("hello") {
        respondWithMediaType(`text/html`) { // XML is marshalled to `text/xml` by default, so we simply override here
          complete {
            <html>
              <h1>Say hello to <em>spray</em> on <em>spray-can</em>!</h1>
              <p>Login with Google / Facebook OpenID Connect on the OAuth Playground</p>
              <a href={oauthComm.loginUrl}>Login</a>
              <p>(<a href="/stop?method=post">stop server</a>)</p>
            </html>
          }
        }
      } ~
      path("protected") {
        authenticate(OAuth("Realm", oauthComm)) { user =>
          respondWithMediaType(`text/html`) {
            complete {
              <html>
                <h1>Protected resource with user Info</h1>
                <p>User subject: {user.subject}</p>
                <p>(<a href="/stop?method=post">stop server</a>)</p>
              </html>
            }
          }
        }
      } ~
      oauthComm.callBackRoute(callbackRoute)
    } ~
    (post | parameter('method ! "post")) {
      path("stop") {
        complete {
          system.scheduler.scheduleOnce(1.second)(system.shutdown())(system.dispatcher)
          "Shutting down in 1 second..."
        }
      }
    }
  }

}