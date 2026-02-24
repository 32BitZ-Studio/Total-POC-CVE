import { useEffect, useRef, useState } from "react";
import {
  Heading,
  Link as ALink,
  Text,
  VStack,
  Button,
  Image,
  Container,
  useMediaQuery,
  Box,
  Flex,
  Divider,
  HStack,
  Input,
} from "@chakra-ui/react";
import { NavigateFunction, useNavigate } from "react-router-dom";
import Icon from "@mdi/react";
import { mdiHeart } from "@mdi/js";

function toLinkAndScrollUp(nav: NavigateFunction, link: string) {
  window.scrollTo({
    top: 0,
    left: 0,
    behavior: "smooth",
  });
  nav(link);
}

export function Home() {
  const navigate = useNavigate();

  return (
    <Container minH="95vh" p="4">
      <VStack maxW="66vw">
        <Heading>GatorMed</Heading>
        <Text>
          Many medical devices are not designed with security in mind. This has
          led to an ecosystem of devices that are vulnerable to cyber attacks.
        </Text>
        <Text>
          In this project, we aim to create a simulation of one specific
          vulnerability: CVE-2020-27252. This pacemaker vulnerability allows an
          attacker to exploit a race condition in the device's firmware to gain
          unauthorized access to the device.
        </Text>
        <ALink
          textColor="blue"
          href="https://nvd.nist.gov/vuln/detail/CVE-2020-27252"
          textDecoration="underline"
          target="_blank"
          rel="noopener noreferrer"
        >
          Reference from NVD.
        </ALink>
        <Button onClick={() => toLinkAndScrollUp(navigate, "/description")}>
          Get Started
        </Button>
      </VStack>
    </Container>
  );
}

export function Description() {
  const navigate = useNavigate();
  return (
    <Container minH="95vh" p="4">
      <VStack maxW="66vw">
        <Heading size="lg">You Start my Heart</Heading>
        <Image maxH="20rem" src="/pacemaker.png" alt="pacemaker" />
        <Text>
          Pictured above is an example of a <strong>pacemaker</strong>{" "}
          manufactured by a medical device manufacturer called{" "}
          <strong>Medtronic</strong>. Pacemakers are critical medical devices
          that are implanted in patients to regulate their heart rate.
        </Text>
        <Text>
          The pacemaker is a small device that is implanted under the skin near
          the heart. It is connected to the heart with wires that deliver
          electrical signals to the heart muscle to regulate the heartbeat.
        </Text>

        <Text>
          To facilitate easier maintenance, many pacemakers are equipped with
          wireless communication capabilities that allow doctors to monitor and
          adjust the device remotely. This is obviously a very good idea, as
          having to pull the pacemaker out of the patient every time it needs to
          be adjusted would be very inconvenient. However, this also introduces
          a new attack vector: the{" "}
          <strong>wireless communication channel</strong>.
        </Text>

        <Button onClick={() => toLinkAndScrollUp(navigate, "/vuln")}>
          So what went wrong?
        </Button>
      </VStack>
    </Container>
  );
}

export function VulnDescription() {
  const navigate = useNavigate();

  return (
    <Container minH="95vh" p="4">
      <VStack maxW="66vw">
        <Heading size="lg">Time-of-Check, Time-of-Use</Heading>
        <Text>
          CVE-2020-27252 existed because of something called a&nbsp;
          <strong>time-of-check time-of-use</strong> weakness. This sort of
          vulnerability arises when a program checks the state of a resource
          (such as a file or a network connection) and then uses that resource
          in a way that is unsafe.
        </Text>
        <Text>
          In the case of the pacemaker, the device would check the state of the
          wireless communication channel before using anything transmitted over
          it, but the state could change between the time of the check and the
          time of the use. This allowed an attacker to upload malicious firmware
          to the device, which could then be used to take control of the
          pacemaker.
        </Text>

        <Button onClick={() => toLinkAndScrollUp(navigate, "/hack-sim")}>
          Let's simulate this
        </Button>
      </VStack>
    </Container>
  );
}

export function HackSim() {
  const navigate = useNavigate();

  type SimSteps = "intro" | "step1" | "step2" | "step3";

  const [currentStep, setCurrentStep] = useState<SimSteps>("intro");
  const [simButtonLoading, setSimButtonLoading] = useState(false);
  const [heartRate, setHeartRate] = useState(0);
  const [heartRateOverridden, setHeartRateOverridden] = useState(false);
  const [heartMonitorActive, setHeartMonitorActive] = useState(false);
  const monitorMutedRef = useRef<boolean>(false);
  const heartRateInterval = useRef<number | null>(null);
  const bpmOverrideInput = useRef<HTMLInputElement | null>(null);

  function playTone() {
    // Play a 1000 Hz tone for 0.3 seconds, wait for 0.1 seconds, then play a 2000 Hz tone for 0.3 seconds
    if (!heartMonitorActive || monitorMutedRef.current) return;
    const audioContext = new AudioContext();
    const gainNode = audioContext.createGain();
    gainNode.gain.value = 0.1;
    const oscillator1 = audioContext.createOscillator();
    oscillator1.frequency.value = 1005;
    oscillator1.connect(gainNode);
    gainNode.connect(audioContext.destination);
    oscillator1.start();

    setTimeout(() => {
      oscillator1.stop();
    }, 150);
  }

  useEffect(() => {
    if (heartRateOverridden) return;

    if (heartRateInterval.current) return;
    // set heart rate to a random value between 60 and 70
    const bpm = Math.floor(Math.random() * 10) + 60;
    const bpmMs = 60000 / bpm;
    heartRateInterval.current = setInterval(() => {
      playTone();
      setHeartRate(bpm);
    }, bpmMs);

    return () => {
      if (heartRateInterval.current) {
        clearInterval(heartRateInterval.current);
        heartRateInterval.current = null;
      }
    };
  }, [heartRate, heartRateOverridden]);

  const steps = {
    intro: {
      heading: "Introduction",
      content: (
        <>
          <Text>
            In this simulation, you will be able to upload a firmware image to a
            simulated pacemaker device. The firmware image will be uploaded over
            a wireless connection to the device.
          </Text>
          <Text>
            The console on the left will show you the progress of the firmware
            upload. It's a facsimile of what the MyCareLink5000 - the uploading
            tool impacted by the vulnerability - might look like.
          </Text>

          <Button colorScheme="green" onClick={() => setCurrentStep("step1")}>
            Start simulation
          </Button>
        </>
      ),
    },
    step1: {
      heading: "Step 1: Connect to the device",
      content: (
        <>
          <Text>
            The first step is to connect to the device. This will simulate the
            process of connecting to the pacemaker over a wireless connection.
          </Text>
          <Text>Click the button below to connect to the device.</Text>
          <Button
            colorScheme="green"
            onClick={() => connectToDevice()}
            isLoading={simButtonLoading}
          >
            Connect to device
          </Button>
        </>
      ),
    },
    step2: {
      heading: "Step 2: Upload the firmware",
      content: (
        <>
          <Text>
            The next step is to upload the firmware image to the device. This
            will simulate the process of uploading the malicious firmware to the
            pacemaker.
          </Text>
          <Text>
            Since this exploit is based on a time-of-check time-of-use
            vulnerability, the firmware image will be uploaded to the device
            after the device has checked the state of the wireless connection.
          </Text>
          <Button
            colorScheme="green"
            onClick={() => startFirmwareUpload()}
            isLoading={simButtonLoading}
          >
            Start firware upload process
          </Button>
        </>
      ),
    },
    step3: {
      heading: "Step 3: Exploit your access",
      content: (
        <>
          <Text>
            The firmware upload process is complete. The device has been
            compromised and unauthorized access has been gained.
          </Text>
          <Text>
            Now you can do whatever you want with the device. For example, you
            could override the heart rate to a dangerous level.
          </Text>
          <Input placeholder="Enter BPM" ref={bpmOverrideInput} type="number" />
          <Button
            colorScheme="red"
            my={4}
            onClick={() => overrideHeartRate()}
            isLoading={simButtonLoading}
          >
            Override heart rate
          </Button>
          <Button colorScheme="red" onClick={finishSim}>
            View impact (Finish Simulation)
          </Button>
        </>
      ),
    },
  };

  function finishSim() {
    if (heartRateInterval.current) clearInterval(heartRateInterval.current);
    toLinkAndScrollUp(navigate, "/impact");
  }

  function connectToDevice() {
    setSimButtonLoading(true);
    createConsoleEntry("Connecting to device...", "info");
    setTimeout(() => {
      setSimButtonLoading(false);
      createConsoleEntry("Connected to device!", "info");
      setCurrentStep("step2");
      setHeartMonitorActive(true);
    }, 2000);
  }

  function startFirmwareUpload() {
    // Since this is a TOCTOU vulnerability, we need to upload the firmware after the device has checked the state of the connection
    setSimButtonLoading(true);
    createConsoleEntry("Checking connection state...", "info");
    setTimeout(() => {
      createConsoleEntry("Connection state: OK", "info");
      createConsoleEntry("Starting firmware upload process...", "info");
      setTimeout(() => {
        setSimButtonLoading(false);
        createConsoleEntry("Firmware upload complete!", "info");
        createConsoleEntry(
          "Device compromised! Unauthorized access gained.",
          "error"
        );
        setCurrentStep("step3");
      }, 4000);
    }, 2000);
  }

  function overrideHeartRate() {
    const newBpm = parseInt(bpmOverrideInput.current?.value || "0");
    if (isNaN(newBpm) || newBpm <= 0 || !Number.isInteger(newBpm)) {
      createConsoleEntry(
        "Invalid BPM value entered. Please enter a positive integer.",
        "error"
      );
      return;
    }

    setHeartRateOverridden(true);
    setHeartRate(newBpm);
    createConsoleEntry(`Heart rate overridden to ${newBpm} BPM`, "info");
    const dangerWord = newBpm > 100 ? "high" : "low";
    if (newBpm > 100 || newBpm < 60) {
      createConsoleEntry(
        `Heart rate is abnormally ${dangerWord}! Please consult a doctor immediately.`,
        "warn"
      );
    }

    if (heartRateInterval.current) clearInterval(heartRateInterval.current);
    const bpmIntervalMs = 60000 / newBpm;

    heartRateInterval.current = setInterval(() => {
      playTone();
      setHeartRate(newBpm);
    }, bpmIntervalMs);
  }

  function createConsoleEntry(
    message: string,
    severity: "info" | "warn" | "error"
  ) {
    const logContainer = document.getElementById("log_container");
    if (!logContainer) return;

    const timestamp = new Date().toLocaleTimeString();

    const logEntry = document.createElement("p");
    logEntry.style.fontFamily = "monospace";
    switch (severity) {
      case "info":
        logEntry.style.color = "black";
        message = `[INFO] ${timestamp} - ${message}`;
        break;
      case "warn":
        logEntry.style.color = "orange";
        message = `[WARN] ${timestamp} - ${message}`;
        break;
      case "error":
        logEntry.style.color = "red";
        message = `[ERROR] ${timestamp} - ${message}`;
        break;
    }
    logEntry.innerText = message;
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
  }

  return (
    <Container minH="95vh" p="4">
      <VStack>
        <Heading size="lg">HackSim</Heading>
        <HStack>
          {/* console */}
          <ContainerBlock
            heading="MyCareLink 5000 - Firmware Upload Console"
            width="40vw"
          >
            <Box
              bg="gray.100"
              p="2"
              rounded="lg"
              mt="auto"
              id="log_container"
              overflowY="scroll"
              flex="1"
            >
              {/* Log entries go here */}
            </Box>
          </ContainerBlock>

          <ContainerBlock
            heading={steps[currentStep].heading}
            havePadding
            width="40vw"
          >
            {steps[currentStep].content}
          </ContainerBlock>
        </HStack>

        {heartMonitorActive && (
          <ContainerBlock heading="Heart Rate Monitor" width="80vw" havePadding>
            <Icon path={mdiHeart} size={2} color="red" />
            <Heading
              size="sm"
              textColor={heartRate > 100 || heartRate < 60 ? "orange" : "blue"}
            >
              {heartRate} BPM
            </Heading>

            <Button
              onClick={() =>
                (monitorMutedRef.current = !monitorMutedRef.current)
              }
            >
              Toggle Mute
            </Button>
          </ContainerBlock>
        )}
      </VStack>
    </Container>
  );
}

function ContainerBlock({
  children,
  heading,
  width,
  havePadding,
}: {
  children: React.ReactNode;
  heading: string;
  width?: string;
  havePadding?: boolean;
}) {
  const isMediumScreen = useMediaQuery("(max-width: 663px)")[0];
  return (
    <Flex
      w={width || (isMediumScreen ? "90vw" : "40vw")}
      h="400px"
      borderWidth="1px"
      borderRadius="lg"
      direction="column"
      p={havePadding ? "2" : "0"}
    >
      <Heading
        size="sm"
        pl={havePadding ? "0" : "2"}
        pt={havePadding ? "0" : "2"}
      >
        {heading}
      </Heading>
      <Divider mt="2" mb="2" />
      {children}
    </Flex>
  );
}

export function Impact() {
  const navigate = useNavigate();
  return (
    <Container minH="95vh" p="4">
      <VStack maxW="66vw">
        <Heading size="lg">Impacts</Heading>

        <Icon path={mdiHeart} color="green" size={10} />
        <Text>
          Thankfully, due to quick remediation on Medtronic's part, there are no
          known cases of CVE-2020-27252 being used to damage someone's heart or
          equipment.
        </Text>
        <Text>
          However, this exploit does highlight the importance of security in
          medical devices. If a malicious actor were to exploit this
          vulnerability, they could potentially cause serious harm to the
          patient.
        </Text>
        <Text>
          This is why it is important for medical device manufacturers to take
          security seriously and ensure that their devices are secure against
          cyber attacks.
        </Text>

        <Text as="i">
          Created by Ethan Hanlon for CSC 699 at San Francisco State University.
        </Text>
        <ALink
          textColor="blue"
          href="https://github.com/OccultSlolem/GatorMed"
          target="_blank"
          rel="noopener noreferrer"
        >
          View source code on GitHub
        </ALink>

        <Button onClick={() => toLinkAndScrollUp(navigate, "/")}>
          Back to Home
        </Button>
      </VStack>
    </Container>
  );
}
