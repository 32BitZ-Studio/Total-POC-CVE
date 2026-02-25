import axios from "axios";
import Cookies from "cookies";
import { GetServerSideProps } from "next";
import { MouseEventHandler, useState } from "react";
import JSONPretty from "react-json-pretty";

export const getServerSideProps: GetServerSideProps = async ({ req, res }) => {
  const cookies = new Cookies(req, res);
  cookies.set("XSRF-TOKEN", "CREDENTIAL_TOKEN", {
    domain: "app.localhost",
    sameSite: "strict",
    httpOnly: false, // HTTPOnly=trueの場合はaxiosかJSでCookieを操作できないので脆弱性は発生しない
  });

  return { props: {} };
};

const Home = () => {
  const [data, setData] = useState("");
  const instance = axios.create({
    withCredentials: true,
  });
  const handleClick: MouseEventHandler<HTMLButtonElement> = async () => {
    const res = await instance.get("http://whoami.localhost/api");
    setData(res.data);
  };

  return (
    <main>
      <button onClick={handleClick}>
        http://whoami.localhostへアクセスする
      </button>
      <JSONPretty id="json-pretty" data={data}></JSONPretty>
    </main>
  );
};

export default Home;
