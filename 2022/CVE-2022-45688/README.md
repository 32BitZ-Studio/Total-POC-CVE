## json.org CVE-2022-45688 true positive

The project illustrates [CVE-2022-45688](https://nvd.nist.gov/vuln/detail/CVE-2022-45688)  in [json.org](https://mvnrepository.com/artifact/org.json/json/20220924) -- there is a simple application
`XML2JSONConverter` to read XML from input, convert it to JSON and 
pretty-print it to the console. 

Using malicious input, the application crashes with a stackoverflow. 

The test case `CVE202245688Test` illustrates this behaviour, it 
can be executed by running `mvn test`.

### Running Software Composition Analyses

There are several sh scripts to run different analyses, result resports can be found in `scan-results`.

### Generating the SBOM

The `pom.xml` has a plugin to generate a [SBOM](https://www.cisa.gov/sbom) in [CycloneDX](https://cyclonedx.org/) format. 
To do this, run `mvn cyclonedx:makePackageBom`, the SBOM can be found in 
`target/` in `json` and `xml` format.

