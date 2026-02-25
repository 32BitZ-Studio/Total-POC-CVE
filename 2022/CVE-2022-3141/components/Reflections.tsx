import React, { FC, RefObject } from "react";

type SectionRefs = {
  overview: RefObject<HTMLElement | null>;
  flaw: RefObject<HTMLElement | null>;
  exploit: RefObject<HTMLElement | null>;
  fix: RefObject<HTMLElement | null>;
  reflections: RefObject<HTMLElement | null>;
};
interface ReflectionsProps {
  sectionRefs: SectionRefs;
}

const Reflections: React.FC<ReflectionsProps> = ({ sectionRefs }) => {
  return (
    <section
      id="reflections"
      ref={sectionRefs.reflections}
      className="mb-12 scroll-mt-24"
    >
      <h2 className="text-3xl font-bold text-slate-900 mb-8 text-center">
        Key Reflections & Takeaways
      </h2>
      <div className="grid md:grid-cols-3 gap-8 text-center">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 text-blue-600 mx-auto mb-4">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              className="lucide lucide-settings-icon lucide-settings"
            >
              <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
              <circle cx="12" cy="12" r="3" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold text-slate-800 mb-2">
            Technical Insights
          </h3>
          <p className="text-slate-600">
            Security controls are not one-size-fits-all. A function like
            `sanitize_text_field` is for preventing XSS, not SQLi. Context is
            everything.
          </p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 text-blue-600 mx-auto mb-4">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              className="lucide lucide-swords-icon lucide-swords"
            >
              <polyline points="14.5 17.5 3 6 3 3 6 3 17.5 14.5" />
              <line x1="13" x2="19" y1="19" y2="13" />
              <line x1="16" x2="20" y1="16" y2="20" />
              <line x1="19" x2="21" y1="21" y2="19" />
              <polyline points="14.5 6.5 18 3 21 3 21 6 17.5 9.5" />
              <line x1="5" x2="9" y1="14" y2="18" />
              <line x1="7" x2="4" y1="17" y2="20" />
              <line x1="3" x2="5" y1="19" y2="21" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold text-slate-800 mb-2">
            Challenges
          </h3>
          <p className="text-slate-600">
            Replicating environments with specific vulnerable software versions
            can be challenging but is a critical skill for analysis and
            verification.
          </p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 text-blue-600 mx-auto mb-4">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              className="lucide lucide-trending-up-icon lucide-trending-up"
            >
              <path d="M16 7h6v6" />
              <path d="m22 7-8.5 8.5-5-5L2 17" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold text-slate-800 mb-2">
            Personal Growth
          </h3>
          <p className="text-slate-600">
            This analysis bridges theory and practice, solidifying the
            importance of manual code review alongside automated tooling.
          </p>
        </div>
      </div>
    </section>
  );
};

export default Reflections;
