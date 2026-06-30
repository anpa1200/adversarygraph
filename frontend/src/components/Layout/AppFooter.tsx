export function AppFooter() {
  return (
    <footer className="shrink-0 border-t border-gray-800 bg-mitre-navy/95 px-6 py-2 text-[11px] text-gray-500">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span>
          Copyright (c) {new Date().getFullYear()}{' '}
          <a
            href="https://1200km.com/about.html"
            target="_blank"
            rel="noreferrer"
            className="font-medium text-gray-400 transition-colors hover:text-mitre-accent"
          >
            Andrey Pautov
          </a>{' '}
          / 1200km. All rights reserved.
        </span>
        <a
          href="https://1200km.com"
          target="_blank"
          rel="noreferrer"
          className="font-medium text-gray-400 transition-colors hover:text-mitre-accent"
        >
          1200km.com
        </a>
      </div>
    </footer>
  );
}
