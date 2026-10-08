/** Lightweight, inline SVG introduction; no external images or runtime animation libraries. */
export function DashboardIntro() {
  return (
    <section
      aria-labelledby="visual-intro-title"
      className="relative mb-5 overflow-hidden rounded-2xl border border-accent-cyan/20 bg-gradient-to-br from-surface-800 via-surface-800 to-[#171430]"
    >
      <div className="relative grid items-center gap-4 p-6 lg:grid-cols-2 lg:gap-8 lg:p-8">
        <div className="relative z-10">
          <div className="mb-3 font-mono text-[11px] uppercase tracking-[.24em] text-accent-cyan">
            Static analysis · Graph inference · Content integrity
          </div>
          <h2 id="visual-intro-title" className="max-w-xl text-2xl font-bold tracking-tight text-white lg:text-3xl">
            Make opaque JavaScript inspectable.
          </h2>
          <p className="mt-3 max-w-lg text-sm leading-relaxed text-gray-400">
            Explore inferred module structure and candidate names across versions.
            Source remains data. Confidence is a review signal, not verified accuracy.
          </p>
          <div className="mt-4 flex flex-wrap gap-2 text-[11px] font-mono">
            <span className="rounded-full border border-accent-cyan/25 px-3 py-1 text-accent-cyan">01 Parse</span>
            <span className="rounded-full border border-accent-cyan/25 px-3 py-1 text-accent-cyan">02 Partition</span>
            <span className="rounded-full border border-accent-purple/30 px-3 py-1 text-accent-purple">03 Review</span>
          </div>
        </div>
        <svg
          viewBox="0 0 540 215"
          role="img"
          aria-labelledby="visual-svg-title visual-svg-desc"
          className="h-auto w-full max-w-[580px]"
        >
          <title id="visual-svg-title">JavaScript source intelligence graph</title>
          <desc id="visual-svg-desc">Animated references flow from a compact code block through a small relationship graph into proposed modules.</desc>
          <defs>
            <linearGradient id="visual-gradient" x1="0" y1="0" x2="1" y2="0">
              <stop stopColor="#00e5ff" />
              <stop offset=".6" stopColor="#7ccfff" />
              <stop offset="1" stopColor="#b388ff" />
            </linearGradient>
          </defs>
          <rect x="4" y="48" width="150" height="128" rx="14" fill="#0d2434" stroke="#32617a" />
          <text x="18" y="71" fontSize="12" fill="#65dae9" fontFamily="monospace">INPUT</text>
          <text x="18" y="104" fontSize="11" fill="#d1edf5" fontFamily="monospace">a=(b)=&gt;b.x</text>
          <text x="18" y="128" fontSize="11" fill="#8fa8be" fontFamily="monospace">q=r=&gt;r+1</text>
          <text x="18" y="152" fontSize="10" fill="#bb978d" fontFamily="monospace">source bytes</text>
          <path d="M157 111H194" fill="none" stroke="url(#visual-gradient)" strokeWidth="2.5" className="visual-trace" />
          <g fill="none" stroke="#6683ad" strokeWidth="1.6">
            <path d="M210 111L245 68L299 98L347 58" />
            <path d="M210 111L246 151L299 98L346 157" />
            <path d="M245 68L246 151L347 58L346 157" opacity=".4" />
          </g>
          <g fill="#42dfdb">
            <circle cx="210" cy="111" r="5" className="visual-pulse" />
            <circle cx="245" cy="68" r="4" />
            <circle cx="246" cy="151" r="4" />
            <circle cx="299" cy="98" r="6" className="visual-pulse" />
          </g>
          <g fill="#b388ff">
            <circle cx="347" cy="58" r="4" />
            <circle cx="346" cy="157" r="4" />
          </g>
          <text x="218" y="195" fontSize="10" fill="#90a6be" fontFamily="monospace">REFERENCE GRAPH</text>
          <path d="M351 111H387" fill="none" stroke="url(#visual-gradient)" strokeWidth="2.5" className="visual-trace" />
          <rect x="391" y="48" width="146" height="128" rx="14" fill="#171a37" stroke="#675a98" />
          <text x="406" y="71" fontSize="12" fill="#c5a9f7" fontFamily="monospace">CANDIDATES</text>
          <text x="406" y="101" fontSize="11" fill="#e7e8fc" fontFamily="monospace">router.js</text>
          <text x="406" y="127" fontSize="11" fill="#e7e8fc" fontFamily="monospace">context.js</text>
          <text x="406" y="151" fontSize="10" fill="#d3b18e" fontFamily="monospace">verify separately</text>
        </svg>
      </div>
    </section>
  );
}
