import { CodeBlock } from "@/helper/codeBlock";
import React, { FC, RefObject } from "react";


type SectionRefs = {
  overview: RefObject<HTMLElement | null>;
  flaw: RefObject<HTMLElement | null>;
  exploit: RefObject<HTMLElement | null>;
  fix: RefObject<HTMLElement | null>;
  reflections: RefObject<HTMLElement | null>;
};

interface FlawProps {
  sectionRefs: SectionRefs;
  reportData: {
    flaw: {
      vulnerableCode: string;
      helperFunction: string;
      explanation: string;
    };
  };
}

const Flaw: FC<FlawProps> = ({ sectionRefs, reportData }) => {
  return (
    <section id="flaw" ref={sectionRefs.flaw} className="mb-24 scroll-mt-24">
      <h2 className="text-3xl font-bold text-slate-900 mb-8 text-center">
        The Flaw: Improper Sanitization
      </h2>
      <p className="text-center max-w-3xl mx-auto text-slate-600 mb-12">
        The vulnerability lies in how the plugin handles user-supplied language
        codes. A key function, `sanitize_text_field()`, is misused, failing to
        escape backticks (`) and allowing an attacker to break out of the SQL
        query.
      </p>
      <div className="bg-white p-6 rounded-lg shadow-md">
        <div className="grid lg:grid-cols-2 gap-8 items-start">
          <div className="w-full overflow-x-scroll sm:overflow-hidden ">
            <p className="text-sm font-semibold mb-2 text-slate-600">
              Vulnerable Function:
            </p>
            <CodeBlock code={reportData.flaw.vulnerableCode} />
            <p className="text-sm font-semibold mt-4 mb-2 text-slate-600">
              Helper Function:
            </p>
            <CodeBlock code={reportData.flaw.helperFunction} />
          </div>
          <div className=" h-full flex items-center">
            <div className="bg-amber-50 border-l-4 border-amber-400 p-4 rounded-r-lg mt-6 md:mt-0">
              <h4 className="font-bold text-amber-900">The Core Flaw</h4>
              <p
                className="text-amber-800 mt-2"
                dangerouslySetInnerHTML={{
                  __html: reportData.flaw.explanation,
                }}
              ></p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Flaw;
