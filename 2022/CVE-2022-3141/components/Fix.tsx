import { CodeBlock } from "@/helper/codeBlock";
import React, { FC, RefObject } from "react";


type SectionRefs = {
  overview: RefObject<HTMLElement | null>;
  flaw: RefObject<HTMLElement | null>;
  exploit: RefObject<HTMLElement | null>;
  fix: RefObject<HTMLElement | null>;
  reflections: RefObject<HTMLElement | null>;
};

interface FixProps {
  sectionRefs: SectionRefs;
  reportData: {
    fix: {
      vulnerableCode: string;
      patchedCode: string;
    };
  };
}

const Fix: React.FC<FixProps> = ({ sectionRefs, reportData }) => {
  return (
    <section id="fix" ref={sectionRefs.fix} className="mb-24 scroll-mt-24">
      <h2 className="text-3xl font-bold text-slate-900 mb-8 text-center">
        The Fix: Whitelisting Input
      </h2>
      <p className="text-center max-w-3xl mx-auto text-slate-600 mb-12">
        The vulnerability was patched in version 2.3.3 by introducing a new
        validation function that whitelists allowed characters for language
        codes, effectively blocking malicious input.
      </p>
      <div className="grid md:grid-cols-2 gap-8  w-full ">
        <div className="w-full sm:overflow-hidden overflow-x-scroll">
          <h3 className="text-xl font-semibold text-slate-800 mb-4 text-center">
            Vulnerable Code
          </h3>
          <CodeBlock code={reportData.fix.vulnerableCode} />
        </div>
        <div className="w-full sm:overflow-hidden overflow-x-scroll">
          <h3 className="text-xl font-semibold text-slate-800 mb-4 text-center">
            Patched Code
          </h3>
          <CodeBlock code={reportData.fix.patchedCode} />
        </div>
      </div>
     
    </section>
  );
};

export default Fix;
