import { describe, it, expect } from 'vitest';
import { listApplications, listCategories, appDomains, categoryDomains } from './appsignatures.mjs';

describe('app/URL signature catalog', () => {
  it('lists applications with name/category/risk, sorted by name', () => {
    const apps = listApplications();
    const names = apps.map(a => a.name);
    expect(names).toContain('YouTube');
    expect(names).toContain('Netflix');
    expect([...names].sort((a, b) => a.localeCompare(b))).toEqual(names); // sorted
    const yt = apps.find(a => a.name === 'YouTube');
    expect(yt).toMatchObject({ category: 'streaming', risk: 3 });
  });

  it('has a substantial catalog across many categories', () => {
    expect(listApplications().length).toBeGreaterThan(100);
    expect(listCategories()).toEqual(expect.arrayContaining(['streaming', 'social', 'gaming', 'messaging', 'vpn-proxy', 'remote-access', 'ai']));
  });

  it('maps an application to all its identifying domains', () => {
    expect(appDomains('YouTube')).toEqual(expect.arrayContaining(['youtube.com', 'googlevideo.com', 'ytimg.com']));
    expect(appDomains('Nonexistent App')).toEqual([]);
  });

  it('maps a category to its member domains', () => {
    const streaming = categoryDomains('streaming');
    expect(streaming).toContain('netflix.com');
    expect(streaming).toContain('youtube.com');
    expect(categoryDomains('nope')).toEqual([]);
  });
});
