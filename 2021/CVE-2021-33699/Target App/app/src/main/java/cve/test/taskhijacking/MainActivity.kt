package cve.test.taskhijacking

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import cve.test.taskhijacking.ui.theme.TaskhijackingTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

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
                if (email == "admin@email.com" && password == "admin") {
                    Toast.makeText(this, "Login Successful", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Invalid email or password", Toast.LENGTH_SHORT).show()
                }
            }
        }

        forgotPasswordButton.setOnClickListener {
            Toast.makeText(this, "Forgot Password \"admin\"", Toast.LENGTH_SHORT).show()
        }

        forgotIdButton.setOnClickListener {
            Toast.makeText(this, "Forgot ID \"admin@email.com\"", Toast.LENGTH_SHORT).show()
        }


    }
}