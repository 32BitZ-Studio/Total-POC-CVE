package com.example

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting() {
    routing {
        get("/") {
            call.respondText("Hello World!")
        }
        
        post("/xml") {
            try {
                println("=== /xml endpoint called ===")
                println("Content-Type: ${call.request.contentType()}")
                println("Content-Length: ${call.request.headers["Content-Length"]}")
                
                // This endpoint uses ContentNegotiation to deserialize XML to UserData
                // It will trigger the XXE vulnerability through the VulnerableXmlConverter
                println("About to call call.receive<UserData>()")
                val userData = call.receive<UserData>()
                println("Successfully received UserData: $userData")
                call.respondText("Received user: ${userData.name} with email: ${userData.email}")
            } catch (e: Exception) {
                println("Error in /xml endpoint: ${e.message}")
                println("Exception type: ${e::class.simpleName}")
                println("Stack trace: ${e.stackTrace.take(5).joinToString("\n")}")
                call.respondText("Error processing XML: ${e.message}")
            }
        }
        
        post("/xml-raw") {
            try {
                // This endpoint processes raw XML text without ContentNegotiation
                // It won't trigger XXE because it doesn't parse the XML
                val xmlContent = call.receiveText()
                call.respondText("Received XML content: $xmlContent")
            } catch (e: Exception) {
                call.respondText("Error processing XML: ${e.message}")
            }
        }
        
        post("/xml-vulnerable") {
            try {
                println("=== /xml-vulnerable endpoint called ===")
                // This endpoint explicitly uses ContentNegotiation to process any XML
                // and demonstrates the XXE vulnerability more clearly
                val result = call.receive<String>()
                println("Received result: $result")
                call.respondText("Processed XML result: $result")
            } catch (e: Exception) {
                println("Error in /xml-vulnerable endpoint: ${e.message}")
                call.respondText("Error processing XML: ${e.message}")
            }
        }
        
        post("/xml-direct") {
            try {
                println("=== /xml-direct endpoint called ===")
                // Direct test of our vulnerable XML converter
                val xmlContent = call.receiveText()
                println("Raw XML received: $xmlContent")
                
                // Manually trigger XXE vulnerability
                val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
                factory.isExpandEntityReferences = true
                factory.setFeature("http://xml.org/sax/features/external-general-entities", true)
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true)
                factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true)
                
                val builder = factory.newDocumentBuilder()
                val inputStream = java.io.ByteArrayInputStream(xmlContent.toByteArray())
                val document = builder.parse(inputStream)
                
                val expandedContent = document.documentElement?.textContent ?: "No content"
                println("Expanded content: '$expandedContent'")
                
                call.respondText("XXE Test Result: $expandedContent")
            } catch (e: Exception) {
                println("Error in /xml-direct endpoint: ${e.message}")
                call.respondText("Error processing XML: ${e.message}")
            }
        }
    }
}
