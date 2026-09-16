import { readFile, writeFile } from 'node:fs/promises';

const path = new URL('../marketplace/catalog.json', import.meta.url);
const apps = JSON.parse(await readFile(path, 'utf8'));
for (const app of apps) {
  const response = await fetch(`https://api.github.com/repos/${app.repo}`, {headers: {'Accept':'application/vnd.github+json','User-Agent':'KunPanel-catalog'}});
  if (!response.ok) throw new Error(`${app.repo}: HTTP ${response.status}`);
  const repo = await response.json();
  if (repo.archived) throw new Error(`${app.repo} is archived`);
  app.stars = repo.stargazers_count;
  app.starsChecked = new Date().toISOString().slice(0, 10);
  console.log(`${app.repo}: ${app.stars}`);
}
await writeFile(path, `${JSON.stringify(apps, null, 2)}\n`);
