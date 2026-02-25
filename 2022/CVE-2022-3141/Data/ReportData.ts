export const reportData: ReportData = {
  overview: {
    text: `CVE-2022-3141 describes a critical SQL injection vulnerability in the "TranslatePress" WordPress plugin (versions < 2.3.3). It allows an authenticated user, even with low privileges, to execute arbitrary SQL commands. The flaw stems from improper sanitization of the 'language code' input, allowing an attacker to inject malicious SQL syntax and control the database. This report visualizes the vulnerability's lifecycle: the flaw, the exploit, and the fix.`,
    cvss: {
      score: 8.8,
      vectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      vectorComponents: [
        {
          key: "AV:N",
          name: "Attack Vector",
          value: "Network",
          description: "The vulnerability is exploitable remotely.",
        },
        {
          key: "AC:L",
          name: "Attack Complexity",
          value: "Low",
          description: "No special conditions are required for exploitation.",
        },
        {
          key: "PR:L",
          name: "Privileges Required",
          value: "Low",
          description: "Requires a low-privileged user account.",
        },
        {
          key: "UI:N",
          name: "User Interaction",
          value: "None",
          description: "No action is needed from any other user.",
        },
        {
          key: "S:U",
          name: "Scope",
          value: "Unchanged",
          description:
            "The exploit does not affect components beyond the vulnerable one.",
        },
        {
          key: "C:H",
          name: "Confidentiality",
          value: "High",
          description: "Attacker can read all data from the database.",
        },
        {
          key: "I:H",
          name: "Integrity",
          value: "High",
          description: "Attacker can modify or delete all data.",
        },
        {
          key: "A:H",
          name: "Availability",
          value: "High",
          description: "Attacker can cause a denial of service.",
        },
      ],
    },
  },
  flaw: {
    vulnerableCode: `public function get_all_translation_blocks( $language_code ){
    // The query concatenates user input into the table name
    $query = "SELECT original, id, block_type, status FROM \`" . 
        sanitize_text_field( $this->get_table_name( $language_code ) ) . 
        "\` WHERE block_type = " . self::BLOCK_TYPE_ACTIVE;
    
    $dictionary = $this->db->get_results($query, OBJECT_K);
    return $dictionary;
}`,
    helperFunction: `public function get_table_name($language_code, ...){
    // This function simply concatenates strings
    return $this->db->prefix . 'trp_dictionary_' . 
        strtolower( $default_language ) . '_' . 
        strtolower( $language_code );
}`,
    explanation: `The core issue is that <strong>sanitize_text_field() does not escape backticks (\`)</strong>. An attacker can inject a backtick in the \`language_code\` parameter to close the table name prematurely and then append their own SQL commands.`,
  },
  exploitSteps: [
    {
      title: "Step 1: Environment Setup",
      content:
        "First, we create an isolated lab environment using Docker to host a WordPress instance with a MariaDB database. This prevents any unintended impact on a live system.",
      code: "docker-compose up -d",
    },
    {
      title: "Step 2: Install Vulnerable Plugin",
      content:
        "Next, we install a version of the TranslatePress plugin known to be vulnerable (any version before 2.3.3) onto our WordPress site.",
      code: "Access WP Admin > Plugins > Add New > Upload Plugin",
    },
    {
      title: "Step 3: Intercept Request",
      content:
        "Using a proxy tool like Burp Suite, we intercept the POST request sent when adding a new language. This allows us to see and modify the `trp_settings[translation-languages][]` parameter.",
      code: `POST /wp-admin/options.php HTTP/1.1\nHost: localhost\n...\n\n...&trp_settings[translation-languages][]=en_US&...`,
    },
    {
      title: "Step 4: Inject Payload",
      content:
        "We craft a time-based blind SQL injection payload and insert it into the vulnerable parameter. This payload will cause the database to pause if the injection is successful.",
      code: "Payload: ` OR SLEEP(5)#",
    },
    {
      title: "Step 5: Automate with sqlmap",
      content:
        "To efficiently extract data, we save the request to a file and use `sqlmap`. This tool automates the process of confirming the vulnerability and dumping database contents.",
      code: 'sqlmap -r request.txt -p "trp_settings[translation-languages][]" --dump',
    },
  ],
  fix: {
    vulnerableCode: `public function get_table_name($language_code, ...){
    // No validation is performed on $language_code
    return $this->db->prefix . 'trp_dictionary_' . 
        strtolower( $default_language ) . '_' . 
        strtolower( $language_code );
}`,
    patchedCode: `function trp_is_valid_language_code( $language_code ){
    // Whitelists allowed characters: a-z A-Z 0-9 - _
    if ( !empty($language_code) && 
         !preg_match( '/[^A-Za-z0-9\\-_]/', $language_code ) ){
        return true;
    } else {
        return false;
    }
}
// This function is now called before using the language code.`,
  },
};
