"use client";
import {
  useState,
  useEffect,
  useRef,
  FC,
} from "react";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
  ChartData,
} from "chart.js";
import Flaw from "@/components/Flaw";
import Exploit from "@/components/Exploit";
import Fix from "@/components/Fix";
import Reflections from "@/components/Reflections";
import Header from "@/components/Header";
import { reportData } from "@/Data/ReportData";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

// --- Data Store ---



// --- Main App Component ---
const App: FC = () => {
  const [activeSection, setActiveSection] = useState("overview");
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [currentExploitStep, setCurrentExploitStep] = useState(0);

  const sectionRefs = {
    overview: useRef<HTMLElement | null>(null),
    flaw: useRef<HTMLElement | null>(null),
    exploit: useRef<HTMLElement | null >(null),
    fix: useRef<HTMLElement |null  >(null),
    reflections: useRef<HTMLElement | null>(null),
  };

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      { rootMargin: "-50% 0px -50% 0px" }
    );

    Object.values(sectionRefs).forEach((ref) => {
      if (ref.current) {
        observer.observe(ref.current);
      }
    });

    return () => observer.disconnect();
  }, []);


  const cvssChartData: ChartData<"bar"> = {
    labels: ["CVSS 3.1 Base Score"],
    datasets: [
      {
        label: "Score",
        data: [reportData.overview.cvss.score],
        backgroundColor: ["#ef4444"],
        borderColor: ["#dc2626"],
        borderWidth: 1,
        barThickness: 50,
      },
    ],
  };

  const cvssChartOptions: ChartOptions<"bar"> = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { beginAtZero: true, max: 10, grid: { color: "#e2e8f0" } },
      y: { grid: { display: false } },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: { label: (context) => `Score: ${context.parsed.x}` },
      },
    },
  };

  return (
    <div className="bg-slate-50 text-slate-800 font-sans overflow-x-auto">
      <Header
        activeSection={activeSection}
        isMenuOpen={isMenuOpen}
        onMenuToggle={() => setIsMenuOpen(!isMenuOpen)}
      />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:mt-0 mt-16 ">
        <section className="text-center mb-24">
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 tracking-tight">
            Interactive Analysis: CVE-2022-3141
          </h1>
          <p className="mt-4 max-w-2xl mx-auto text-lg text-slate-600">
            An in-depth look at the authenticated SQL Injection vulnerability in
            the TranslatePress WordPress plugin.
          </p>
        </section>

        <section
          id="overview"
          ref={sectionRefs.overview}
          className="mb-24 b scroll-mt-24"
        >
          <h2 className="text-3xl font-bold text-slate-900 mb-8 text-center">
            Vulnerability Overview
          </h2>
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div className="bg-white p-4 lg:p-8 rounded-lg shadow-md ">
              <p className="text-slate-600  leading-relaxed">
                {reportData.overview.text}
              </p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-slate-800 mb-4 text-center">
                CVSS 3.1 Score: 8.8 (High)
              </h3>
              <div className="relative h-64 w-full max-w-lg mx-auto">
                <Bar options={cvssChartOptions} data={cvssChartData} />
              </div>
              <div className="mt-6 flex flex-wrap justify-center gap-2">
                {reportData.overview.cvss.vectorComponents.map((c) => (
                  <div
                    key={c.key}
                    className="bg-slate-100 text-slate-700 text-xs font-semibold px-2.5 py-1 rounded-full cursor-pointer transition-transform hover:scale-105"
                    title={`${c.name}: ${c.value}\n${c.description}`}
                  >
                    {c.key}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <Flaw sectionRefs={sectionRefs} reportData={reportData} />

        <Exploit
          sectionRefs={sectionRefs}
          reportData={reportData}
          currentExploitStep={currentExploitStep}
          setCurrentExploitStep={setCurrentExploitStep}
        />

        <Fix sectionRefs={sectionRefs} reportData={reportData} />

        <Reflections sectionRefs={sectionRefs} />
      </main>

      <footer className="bg-white border-t border-slate-200">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 text-center text-sm text-slate-500">
          <p>
            Interactive report created based on the "Web Exploitation Evaluation
            Report" for CVE-2022-3141.
          </p>
          <p className="mt-2">
            References:{" "}
            <a
              href="https://nvd.nist.gov/vuln/detail/CVE-2022-3141"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-500 hover:underline"
            >
              NVD
            </a>{" "}
            |{" "}
            <a
              href="https://owasp.org/Top10/A03_2021-Injection/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-500 hover:underline"
            >
              OWASP Injection
            </a>
          </p>
        </div>
      </footer>

    
    </div>
  );
};

export default App;
