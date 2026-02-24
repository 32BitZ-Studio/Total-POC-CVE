import { Box, Flex, Link as ALink, Heading, Text } from "@chakra-ui/react";
import { Link, Outlet } from "react-router-dom";

export default function Layout() {
  return (
    <>
      <Nav />
      <Outlet />
      <Footer />
    </>
  );
}

function Nav() {
  return (
    <Box w="100%" h="50px" bg="blue.500" pl={2}>
      <Link to="/">
        <Heading textColor="white">GatorMed</Heading>
      </Link>
    </Box>
  );
}

function Footer() {
  const currentYear = new Date().getFullYear();
  return (
    <Box w="100%" h="50px" bg="blue.500" pl={2}>
      <Flex align="center">
        <Heading pr="2" textColor="white">
          GatorMed
        </Heading>
        <Text textColor="white">&copy; {currentYear}&nbsp;</Text>
        <ALink
          textColor="beige"
          textDecoration="underline"
          target="_blank"
          rel="noopener noreferrer"
          href="https://ethan-hanlon.xyz"
        >
          Ethan Hanlon
        </ALink>
        <Text px={2}>·</Text>
        <ALink
          textColor="beige"
          textDecoration="underline"
          target="_blank"
          rel="noopener noreferrer"
          href="https://github.com/OccultSlolem/GatorMed"
        >
          Source Code
        </ALink>
      </Flex>
    </Box>
  );
}
