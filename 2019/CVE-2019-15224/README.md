# a malicious rest-client gem

On August 19, 2019, it was discovered that the `rest-client` gem had had [several versions published containing malicious code](https://github.com/rest-client/rest-client/issues/713). In discovering the malicious `rest-client`, several other new gems were determined to be carrying similar code.

Coverage:

+ https://www.securityweek.com/backdoor-found-rest-client-ruby-gem
+ https://www.theregister.co.uk/2019/08/20/ruby_gem_hacked/
+ https://www.macobserver.com/news/ruby-11-backdoors/

This repo is an example of how one could use InSpec to create controls to audit hosts for the presence of malicious versions of `rest-client` and for the other gems discovered during the investigation. The checks require a scan of entire filesystem directory structures. Because this is a slow process, it is recommended that these controls should not be added to continuous system checks.
