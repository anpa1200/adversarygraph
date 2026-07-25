import { Link } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { helpTopics, localRunSections } from '@/config/help';

export function HelpGuide() {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <Header title="Help / Local Guide" />
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-7xl space-y-8">
          <section className="rounded-lg border border-gray-800 bg-gray-950/70 p-6">
            <p className="text-xs font-semibold uppercase tracking-wide text-mitre-accent">Local platform manual</p>
            <h1 className="mt-2 text-3xl font-bold text-white">AdversaryGraph Help</h1>
            <p className="mt-3 max-w-4xl leading-7 text-gray-300">
              This guide explains how to run AdversaryGraph locally and how to use each workspace module. Every
              platform page has a help button in the header with a short module guide and a link back to this page.
            </p>
            <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[
                ['Local URL', 'http://localhost:3000'],
                ['Main workflow', 'Discover -> module -> validate -> export'],
                ['Health', 'Use Self-test and Observability'],
                ['Data sources', 'Manage feeds before deep analysis'],
              ].map(([label, value]) => (
                <div key={label} className="rounded border border-gray-800 bg-gray-900/60 p-4">
                  <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
                  <div className="mt-2 text-sm font-semibold text-gray-100">{value}</div>
                </div>
              ))}
            </div>
            <a
              href="https://github.com/anpa1200/adversarygraph/blob/main/docs/module-reference.md"
              target="_blank"
              rel="noreferrer"
              className="mt-5 inline-flex rounded border border-mitre-accent/50 px-4 py-2 text-sm font-semibold text-mitre-accent hover:border-mitre-accent hover:bg-mitre-accent/10"
            >
              Open detailed module examples and case studies
            </a>
          </section>

          <section className="grid gap-4 lg:grid-cols-2">
            {localRunSections.map(section => (
              <article key={section.title} className="rounded-lg border border-gray-800 bg-gray-950/60 p-5">
                <h2 className="text-lg font-semibold text-white">{section.title}</h2>
                <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-gray-300">
                  {section.body.map(item => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </article>
            ))}
          </section>

          <section className="rounded-lg border border-gray-800 bg-gray-950/60 p-6">
            <h2 className="text-xl font-semibold text-white">Common local commands</h2>
            <div className="mt-4 grid gap-3 lg:grid-cols-2">
              <CommandBlock title="Start or update" command="docker compose up -d --build" />
              <CommandBlock title="Container health" command="docker compose ps" />
              <CommandBlock title="Follow logs" command="docker compose logs -f api frontend worker beat" />
              <CommandBlock title="Stop without deleting volumes" command="docker compose down" />
            </div>
          </section>

          <section>
            <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-mitre-accent">Module guides</p>
                <h2 className="mt-1 text-2xl font-bold text-white">Platform pages and workflows</h2>
              </div>
              <Link to="/troubleshooting" className="rounded border border-gray-700 px-3 py-2 text-sm font-semibold text-gray-300 hover:border-gray-500 hover:text-white">
                Open troubleshooting
              </Link>
            </div>

            <div className="grid gap-4">
              {helpTopics.map(topic => (
                <article key={topic.id} id={topic.id} className="scroll-mt-20 rounded-lg border border-gray-800 bg-gray-950/60 p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h3 className="text-xl font-semibold text-white">{topic.title}</h3>
                      <p className="mt-2 max-w-4xl leading-6 text-gray-300">{topic.summary}</p>
                    </div>
                    <Link to={topic.route} className="rounded bg-mitre-accent px-3 py-2 text-sm font-semibold text-white hover:bg-mitre-accent/90">
                      Open page
                    </Link>
                  </div>

                  <div className="mt-5 grid gap-4 lg:grid-cols-4">
                    <GuideColumn title="Use this when" items={topic.whenToUse} />
                    <GuideColumn title="Workflow" items={topic.workflow} ordered />
                    <GuideColumn title="Outputs" items={topic.outputs} />
                    <GuideColumn title="Analyst tips" items={topic.tips} />
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function CommandBlock({ title, command }: { title: string; command: string }) {
  return (
    <div className="rounded border border-gray-800 bg-black/50 p-4">
      <div className="text-xs uppercase tracking-wide text-gray-500">{title}</div>
      <code className="mt-2 block select-all overflow-x-auto rounded bg-gray-950 px-3 py-2 text-sm text-green-300">{command}</code>
    </div>
  );
}

function GuideColumn({ title, items, ordered = false }: { title: string; items: string[]; ordered?: boolean }) {
  const ListTag = ordered ? 'ol' : 'ul';
  return (
    <div className="rounded border border-gray-800 bg-gray-900/40 p-4">
      <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h4>
      <ListTag className={`mt-3 space-y-2 text-sm leading-6 text-gray-300 ${ordered ? 'list-decimal pl-5' : 'list-disc pl-5'}`}>
        {items.map(item => (
          <li key={item}>{item}</li>
        ))}
      </ListTag>
    </div>
  );
}
