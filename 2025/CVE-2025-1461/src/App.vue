<template>
<v-app id="app">
<v-container>
<h1>
  <small>Reproduction of Vuetify vulnerability:</small>
  No sanitization for <code>eventMoreText</code>
</h1>

<section class="vulnerability-info-section">
  <h2>Vulnerability information</h2>
  <table class="vulnerability-info-table">
    <tr>
      <th>CVE:</th>
      <td><a href="https://www.cve.org/CVERecord?id=CVE-2025-1461">CVE-2025-1461</a></td>
    </tr>
    <tr>
      <th>Type:</th>
      <td>Cross-Site Scripting (XSS)</td>
    </tr>
    <tr>
      <th>Affected versions:</th>
      <td>All Open Source Vuetify 2.x versions prior to Vuetify NES 2.7.3</td>
    </tr>
    <tr>
      <th>Fixed in version:</th>
      <td>Vuetify NES v2.7.3</td>
    </tr>
    <tr>
      <th>Description:</th>
      <td>
        Setting the <code>eventMoreText</code> prop value in VCalendar is not subject to HTML sanitization.
        The text is directly assigned to the <code>innerHTML</code> of the "more events" element, which can lead to XSS attacks.
        <aside>
          <b>NOTE</b><br>
          The vulnerability allows an attacker to inject arbitrary JavaScript that can execute on a number of events, including <code>onload</code>.
        </aside>
      </td>
    </tr>
  </table>
</section>

<section class="repro-instructions-section">
  <h2>Reproduction instructions</h2>
  <p>
    The example below demonstrates how the <code>eventMoreText</code> prop in VCalendar can be exploited for XSS attacks.
  </p>
  <p>
    <b>Steps:</b>
    <ol>
      <li>
        Switch between the tabs to see different implementations.
      </li>
      <li>
        The "Vulnerable Example" tab shows a calendar using a malicious <code>eventMoreText</code> value that contains
        an <code>onclick</code> handler.
      </li>
      <li>
        Click on the "🚨 Click Here" text that appears when there are too many events to display.
        This will execute the injected JavaScript code.
      </li>
      <li>
        The "Default Prop Value" tab shows a calendar with the default <code>eventMoreText</code> for comparison.
      </li>
    </ol>
  </p>
</section>

<section class="repro-content-section">
  <h2>Reproductions <v-chip>VCalendar</v-chip></h2>
  <Reproduction class="mt-4"/>
</section>
</v-container>
</v-app>
</template>

<script>
import Reproduction from './components/Reproduction.vue'

export default {
name: 'App',
components: {
  Reproduction,
},
}
</script>



<style>
/* Styles */
h1 {
  text-align: center;
  margin-bottom: 2rem;
}

h1 > small {
  display: block;
  font-weight: normal;
  font-size: 0.8em;
  margin-bottom: 0;
}

aside {
  border-left: 4px solid #2196f3;
  font-size: 0.9rem;
  margin: 0.5rem 0;
  padding: 0.5rem 1rem;
  background-color: rgba(33, 150, 243, 0.05);
}

code {
  background-color: #f5f5f5;
  padding: 2px 4px;
  border-radius: 3px;
  font-family: monospace;
}

section {
  border-top: 2px solid gray;
  padding: 1rem;
  margin-bottom: 2rem;
}

.vulnerability-info-table {
  border-spacing: 0.5rem;
  margin-right: 1rem;
  width: 100%;
}

.vulnerability-info-table th {
  text-align: left;
  vertical-align: top;
  white-space: nowrap;
  width: 20%;
}

.repro-instructions-section li {
  margin-bottom: 0.5rem;
}
</style>