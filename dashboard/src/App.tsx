import { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import type { VersionData, PageId } from './types';
// Split the heavy decompiler and archive views into route-specific chunks.
const Explorer = lazy(() => import('./pages/Explorer').then((mod) => ({ default: mod.Explorer })));
const Decompiler = lazy(() => import('./pages/Decompiler').then((mod) => ({ default: mod.Decompiler })));
const RvfViewer = lazy(() => import('./pages/RvfViewer').then((mod) => ({ default: mod.RvfViewer })));

const VERSION_IDS = ['v0.2.x', 'v1.0.x', 'v2.0.x', 'v2.1.x'];
const DATA_BASE = '/data';

async function loadVersionData(versionId: string): Promise<VersionData> {
  const base = `${DATA_BASE}/${versionId}`;
  const [metricsResp, readmeResp, manifestResp] = await Promise.all([
    fetch(`${base}/source/metrics.json`),
    fetch(`${base}/README.md`),
    fetch(`${base}/manifest.json`).catch(() => null),
  ]);

  const metrics = await metricsResp.json();
  const readme = await readmeResp.text();
  const manifest = manifestResp?.ok ? await manifestResp.json() : undefined;

  const moduleNames = Object.keys(metrics.modules || {});
  const moduleContents: Record<string, string> = {};

  const loads = moduleNames.map(async (name) => {
    try {
      const resp = await fetch(`${base}/source/${name}.js`);
      if (resp.ok) moduleContents[name] = await resp.text();
    } catch {
      /* module file may not exist */
    }
  });
  await Promise.all(loads);

  return {
    id: versionId,
    label: versionId,
    metrics,
    modules: moduleContents,
    readme,
    manifest,
  };
}

const NAV_ITEMS: { id: PageId; label: string; path: string }[] = [
  { id: 'explorer', label: 'Explorer', path: '/' },
  { id: 'decompiler', label: 'NPM Decompiler', path: '/decompiler' },
  { id: 'rvf-viewer', label: 'RVF Viewer', path: '/rvf' },
];

export default function App() {
  const [versions, setVersions] = useState<VersionData[]>([]);
  const [archiveStatus, setArchiveStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const location = useLocation();

  // NPM analysis is independent of the archived Claude Code data. Fetch archives
  // only when an archive-backed view is first opened; reuse them across routes.
  const needsArchives = location.pathname === '/' || location.pathname.startsWith('/rvf');
  useEffect(() => {
    if (!needsArchives || archiveStatus !== 'idle') return;
    setArchiveStatus('loading');
    Promise.all(VERSION_IDS.map(loadVersionData))
      .then((data) => {
        setVersions(data);
        setArchiveStatus('ready');
      })
      .catch((err) => {
        console.error('Failed to load archive data:', err);
        setArchiveError(err instanceof Error ? err.message : 'Archive data unavailable');
        setArchiveStatus('error');
      });
  }, [needsArchives, archiveStatus]);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="flex-shrink-0 border-b border-surface-600 bg-surface-800/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent-cyan to-accent-purple flex items-center justify-center text-black font-bold text-xl" aria-hidden="true">
              ∞
            </div>
            <h1 className="text-base font-semibold text-gray-100">
              ru<span className="text-accent-cyan glow-cyan">Devolution</span>
            </h1>
            <span className="hidden lg:block text-xs tracking-widest uppercase text-gray-500">Source intelligence</span>
          </div>
          <nav className="flex gap-1">
            {NAV_ITEMS.map((item) => {
              const isActive =
                item.path === '/'
                  ? location.pathname === '/'
                  : location.pathname.startsWith(item.path);
              return (
                <Link
                  key={item.id}
                  to={item.path}
                  className={`px-3 py-1.5 rounded-md text-sm transition-colors ${
                    isActive
                      ? 'bg-accent-cyan/10 text-accent-cyan'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-surface-700'
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1">
        {needsArchives && archiveStatus !== 'ready' ? (
          archiveStatus === 'error' ? (
            <div className="max-w-xl mx-auto my-16 rounded-lg border border-red-500/30 bg-surface-800 p-6 text-center">
              <p className="font-semibold text-red-300">Archive data unavailable</p>
              <p className="mt-2 text-sm text-gray-400">{archiveError}</p>
              <button
                className="mt-4 rounded-lg border border-accent-cyan/40 px-4 py-2 text-accent-cyan hover:bg-accent-cyan/10"
                onClick={() => { setArchiveError(null); setArchiveStatus('idle'); }}
              >
                Retry loading
              </button>
            </div>
          ) : (
            <div className="flex items-center justify-center h-96" role="status" aria-live="polite">
              <div className="text-center">
                <div className="w-8 h-8 border-2 border-accent-cyan/30 border-t-accent-cyan rounded-full animate-spin motion-reduce:animate-none mx-auto mb-3" />
                <p className="text-sm text-gray-500">Loading historical archive…</p>
              </div>
            </div>
          )
        ) : (
          <Suspense fallback={<div role="status" className="p-10 text-center text-sm text-gray-500">Opening workspace…</div>}>
            <Routes>
              <Route path="/" element={<Explorer versions={versions} showToast={showToast} />} />
              <Route path="/decompiler" element={<Decompiler showToast={showToast} />} />
              <Route path="/rvf" element={<RvfViewer versions={versions} showToast={showToast} />} />
            </Routes>
          </Suspense>
        )}
      </main>

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 bg-surface-700 border border-accent-cyan/30 rounded-lg text-sm text-accent-cyan shadow-lg glow-border animate-pulse">
          {toast}
        </div>
      )}
    </div>
  );
}
