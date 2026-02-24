// akka specific
import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
// akka http specific
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives.*
// spray specific (JSON marshalling)
import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport.*
import spray.json.DefaultJsonProtocol.*

final case class User (id: Long, name: String, email: String)

@main def userSerice: Unit = 

  implicit val actorSystem = ActorSystem(Behaviors.empty, "akka-http")
  implicit val userMarshaller: spray.json.RootJsonFormat[User] = jsonFormat3(User.apply)
  
  val content =
    """
      |<html>
      | <head></head>
      | <body>
      |   This is an HTML page served by Akka HTTP!
      | </body>
      |</html>
    """

  val route = get {
    complete(
      HttpEntity(
        ContentTypes.`text/html(UTF-8)`,
        content
      )
    )
  }

  val bindFuture = Http().newServerAt("127.0.0.1", 8082).bind(route)

