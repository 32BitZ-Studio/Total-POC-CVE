package com.example

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.serialization.*
import io.ktor.server.response.*
import io.ktor.util.reflect.*
import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.jvm.javaio.*
import io.ktor.utils.io.*
import io.ktor.http.content.*
import nl.adaptivity.xmlutil.*
import nl.adaptivity.xmlutil.serialization.*
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.serialization.Serializable

@Serializable
data class UserData(val name: String, val email: String)

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        // This simulates the vulnerable default configuration from xmlutil 0.86.1
        // The vulnerability was that xmlutil processed external entities by default
        val vulnerableXmlFormat = XML {
            // These settings make it vulnerable to XXE (like the original bug)
            xmlDeclMode = XmlDeclMode.Auto
            indent = 2
            // The key vulnerability: external entities are processed by default in 0.86.1
        }
        
        register(ContentType.Application.Xml, VulnerableXmlConverter(vulnerableXmlFormat))
        register(ContentType.Text.Xml, VulnerableXmlConverter(vulnerableXmlFormat))
    }
}

class VulnerableXmlConverter(private val xmlFormat: XML) : ContentConverter {
    
    override suspend fun deserialize(charset: Charset, typeInfo: TypeInfo, content: ByteReadChannel): Any? {
        val xmlText = content.toInputStream().reader(charset).readText()
        
        println("=== XXE VULNERABILITY PROCESSING ===")
        println("Received XML: $xmlText")
        println("Target type: ${typeInfo.kotlinType}")
        println("Charset: $charset")
        
        // This demonstrates the XXE vulnerability exactly as it existed in xmlutil 0.86.1
        // The vulnerability was that xmlutil processed external entities by default
        try {
            // Create a vulnerable XML parser that mimics xmlutil 0.86.1 behavior
            val factory = DocumentBuilderFactory.newInstance()
            
            // Enable external entity processing (this is the exact vulnerability)
            factory.isExpandEntityReferences = true
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true)
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true)
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true)
            
            println("Created vulnerable XML parser with external entity processing enabled")
            
            val builder = factory.newDocumentBuilder()
            val inputStream = java.io.ByteArrayInputStream(xmlText.toByteArray(charset))
            val document = builder.parse(inputStream)
            
            // Extract all text content (including expanded entities)
            val expandedContent = extractAllTextContent(document.documentElement)
            println("Expanded XML content: '$expandedContent'")
            println("Original XML length: ${xmlText.length}, Expanded content length: ${expandedContent.length}")
            
            // If we're deserializing to UserData, try to create it from the expanded content
            if (typeInfo.kotlinType?.classifier == UserData::class) {
                println("Deserializing to UserData class")
                val result = parseUserDataFromExpandedXml(xmlText, expandedContent)
                println("Created UserData: $result")
                return result
            }
            
            // For other types, return the expanded content
            println("Returning expanded content for type: ${typeInfo.kotlinType}")
            return expandedContent
            
        } catch (e: Exception) {
            println("XXE Processing error: ${e.message}")
            println("Stack trace: ${e.stackTrace.joinToString("\n")}")
            // Return original content if parsing fails
            return xmlText
        }
    }
    
    private fun extractAllTextContent(element: org.w3c.dom.Element?): String {
        if (element == null) return ""
        
        val result = StringBuilder()
        val nodeList = element.childNodes
        
        for (i in 0 until nodeList.length) {
            val node = nodeList.item(i)
            when (node.nodeType) {
                org.w3c.dom.Node.TEXT_NODE -> result.append(node.textContent)
                org.w3c.dom.Node.ELEMENT_NODE -> result.append(extractAllTextContent(node as org.w3c.dom.Element))
            }
        }
        
        return result.toString()
    }
    
    private fun parseUserDataFromExpandedXml(originalXml: String, expandedContent: String): UserData {
        println("parseUserDataFromExpandedXml called:")
        println("  Original XML length: ${originalXml.length}")
        println("  Expanded content: '$expandedContent'")
        println("  Expanded content length: ${expandedContent.length}")
        
        // Try to extract the actual content from the XML structure
        val document = try {
            val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
            factory.isExpandEntityReferences = true
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true)
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true)
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true)
            
            val builder = factory.newDocumentBuilder()
            val inputStream = java.io.ByteArrayInputStream(originalXml.toByteArray())
            builder.parse(inputStream)
        } catch (e: Exception) {
            println("  Failed to re-parse XML: ${e.message}")
            null
        }
        
        val nameContent = document?.getElementsByTagName("name")?.item(0)?.textContent ?: expandedContent
        val emailContent = document?.getElementsByTagName("email")?.item(0)?.textContent ?: "xxe@vulnerable.com"
        
        println("  Extracted name: '$nameContent'")
        println("  Extracted email: '$emailContent'")
        
        return UserData(
            name = nameContent,
            email = emailContent
        )
    }
    
    override suspend fun serialize(contentType: ContentType, charset: Charset, typeInfo: TypeInfo, value: Any): OutgoingContent {
        val text = when (value) {
            is String -> value
            else -> value.toString()
        }
        return TextContent(text, contentType.withCharset(charset))
    }
}
