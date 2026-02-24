# rails-cve-2017-17917
The project demonstrates the replication of a SQL injection vulnerability in the <b>id</b> parameter, and subsequently provides insights into mitigating and resolving this security issue.
https://www.cvedetails.com/cve/CVE-2017-17917/?q=CVE-2017-17917

<b>Stack</b>:

```
  Ruby: 3.2.2
  Rails: 7.0.8
  Docker 24.0.5
  Docker-Compose 1.29.2
  PostgreSQL
```

## [CVE-2017-17917](https://www.cvedetails.com/cve/CVE-2017-17917/?q=CVE-2017-17917)
![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/d601e033-5dd6-410f-b9bf-be32c51b255c)

We selected this CVE to highlight the persisting occurrence of this issue in the latest versions of Rails, reaffirming its relevance of the development best practices.


## Schema from the environment to replicate the vulnerability

![Diagrama sem nome drawio(1)](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/48795586/e6566323-7dae-45b3-bb2e-4849b06cfc43)

## Instructions to replicate this vulnerability.
<b>Requirements: </b>
```
  docker
  docker-compose
```

<b>Steps to build a project</b>:

```
  sudo docker-compose build
```
![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/c1a23f3c-4cee-42e1-b030-1d33a9a7454d)

```
  sudo docker-compose run web bundle install
```

![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/11aa8eb1-37a3-4f42-88e5-a152c04ad4b4)

```
  sudo docker-compose run web rails db:create db:migrate db:seed
```

![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/2757fcc4-a05b-4c6f-a2d2-65f075824343)

```
  sudo docker-compose up
```
![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/3a4d0277-0e9a-40bf-b6b1-d7425051ac50)


Go to http://localhost:3000/

![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/a0e43e0c-b54a-4399-a702-dd28dcbded8d)

![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/f8e4e76e-f7e3-4757-a59c-2052c1c30e3f)

SQL Injection param `1 OR id > 1`

![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/df1c162f-0ce9-4038-bc26-bc56996f2281)

## Assessing the risks of the vulnerability in a production environment.
With this SQL injection, an attacker can retrieve user data they wouldn't normally have access to view. <br/>
degree difficulty to execution: <b>easy</b>

## Conclusion
The issue lies in the controller method, specifically when invoking a where clause as follows: <br/>
 ``` @clients = Client.where("id = #{params[:id_search]}") ``` <br/>
 [Link to Code](https://github.com/matiasarenhard/rails-cve-2017-17917/blob/main/app/controllers/clients_controller.rb#L7)
 <br/>

 
The problem is resolved by using the following approach: <br/>
  ```@clients = Client.where(id: "#{params[:id_search]}")``` <br/>
  [Link to Code](https://github.com/matiasarenhard/rails-cve-2017-17917/blob/main/app/controllers/clients_controller.rb#L10)
  
## Tests 
```
  sudo docker-compose run web rspec
```
![image](https://github.com/matiasarenhard/rails-cve-2017-17917/assets/14844393/841d0afc-b84b-46ee-9e1f-b6cdbc876a21)




