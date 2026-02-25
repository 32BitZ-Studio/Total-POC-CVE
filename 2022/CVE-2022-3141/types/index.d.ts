interface HeaderProps {
  activeSection: string;
  isMenuOpen: boolean;
  onMenuToggle: () => void;
}

interface CVSSComponent {
  key: string;
  name: string;
  value: string;
  description: string;
}

interface ExploitStep {
  title: string;
  content: string;
  code: string;
}

interface ReportData {
  overview: {
    text: string;
    cvss: {
      score: number;
      vectorString: string;
      vectorComponents: CVSSComponent[];
    };
  };
  flaw: {
    vulnerableCode: string;
    helperFunction: string;
    explanation: string;
  };
  exploitSteps: ExploitStep[];
  fix: {
    vulnerableCode: string;
    patchedCode: string;
  };
}