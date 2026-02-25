import React, { FC } from 'react'

const Header: FC<HeaderProps> = ({
  activeSection,
  isMenuOpen,
  onMenuToggle,
}) => {
  const navLinks = [
    { href: "#overview", label: "Overview" },
    { href: "#flaw", label: "The Flaw" },
    { href: "#exploit", label: "The Exploit" },
    { href: "#fix", label: "The Fix" },
    { href: "#reflections", label: "Reflections" },
  ];

  return (
    <header className="bg-white/80 backdrop-blur-lg fixed w-full sm:sticky top-0 z-50 border-b border-slate-200  ">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <span className="font-bold text-lg text-slate-900">
              CVE-2022-3141
            </span>
          </div>
          <div className="hidden md:block">
            <div className="ml-10 flex items-baseline space-x-4">
              {navLinks.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeSection === link.href.substring(1)
                      ? "text-blue-500 font-semibold"
                      : "text-slate-600 hover:text-blue-500"
                  }`}
                >
                  {link.label}
                </a>
              ))}
            </div>
          </div>
          <div className="-mr-2 flex md:hidden">
            <button
              type="button"
              onClick={onMenuToggle}
              className="bg-white inline-flex items-center justify-center p-2 rounded-md text-slate-400 hover:text-slate-500 hover:bg-slate-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              aria-controls="mobile-menu"
              aria-expanded={isMenuOpen}
            >
              <span className="sr-only">Open main menu</span>
              {isMenuOpen ? (
                <svg
                  className="block h-6 w-6"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              ) : (
                <svg
                  className="block h-6 w-6"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                </svg>
              )}
            </button>
          </div>
        </div>
      </nav>
      {isMenuOpen && (
        <div className="md:hidden" id="mobile-menu">
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className={`block px-3 py-2 rounded-md text-base font-medium ${
                  activeSection === link.href.substring(1)
                    ? "text-blue-500 bg-blue-50"
                    : "text-slate-600 hover:text-blue-500 hover:bg-slate-50"
                }`}
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>
      )}
    </header>
  );
};

export default Header