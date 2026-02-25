# Vuetify VCalendar XSS Vulnerability POC (CVE-2025-1461)

This repository contains a proof of concept demonstrating the XSS vulnerability in Vuetify's VCalendar component, specifically in the `eventMoreText` prop.

## Vulnerability Details

- **CVE ID**: CVE-2025-1461
- **Affected Versions**: >=2.0.0 <3.0.0
- **Severity**: Medium (4.6)
- **Category**: Cross-Site Scripting (XSS)

## Prerequisites

- Node.js (v14-16)
- npm

## Installation

1. Clone this repository:

  ```bash
  git clone https://github.com/neverendingsupport/nes-vuetify-cve-2025-1461
  cd nes-vuetify-pocs
  ```

2. Install dependencies:

  ```bash
  npm install
  ```

## Running the POC

1. Start the development server:

  ```bash
  npm run dev
  ```

2. Open your browser and navigate to `http://localhost:3000`

## Understanding the Vulnerability

The POC demonstrates how malicious HTML/JavaScript can be injected through the `eventMoreText` prop of the VCalendar component. When there are more events than can be displayed, the calendar shows a "more events" link that can execute arbitrary JavaScript code.

## Related Links

- [Vuetify Documentation](https://v2.vuetifyjs.com/)
- [Vuetify Calendar API](https://v2.vuetifyjs.com/en/api/v-calendar/)
- [Vuetify NES](https://herodevs.com/support/vuetify-nes)
- [CVE-2025-1461 Details](https://www.cve.org/CVERecord?id=CVE-2025-1461)
